package taprootassets

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/taprpc/pocketuniverserpc"
	"github.com/lightninglabs/taproot-assets/tapscript"
)

func (r *rpcServer) ComputeVirtualTxSigHash(ctx context.Context,
	req *pocketuniverserpc.ComputeSigHashRequest) (
	*pocketuniverserpc.ComputeSigHashResponse, error) {

	vPkt, err := tappsbt.Decode(req.FundedPsbt)
	if err != nil {
		return nil, fmt.Errorf("error decoding packet: %w", err)
	}

	if len(vPkt.Inputs) == 0 {
		return nil, fmt.Errorf("packet has no inputs")
	}

    // Get the new asset (output asset)
    newAsset := vPkt.Outputs[0].Asset

	// Construct input set from all input assets
	prevAssets := make(commitment.InputSet, len(vPkt.Inputs))
	for idx := range vPkt.Inputs {
		vIn := vPkt.Inputs[idx]
		prevAssets[vIn.PrevID] = vIn.Asset()
	}

    // Create the virtual transaction
    virtualTx, _, err := tapscript.VirtualTx(newAsset, prevAssets)
    if err != nil {
        return nil, fmt.Errorf("error creating virtual tx: %w", err)
    }

    // Map each PrevID to its witness index in the new asset to ensure we use
    // the correct leaf index for multi-input sighash binding.
    witnessIndexByPrevID := make(map[asset.PrevID]uint32)
    for idx := range newAsset.Witnesses() {
        w := newAsset.Witnesses()[idx]
        if w.PrevID != nil {
            witnessIndexByPrevID[*w.PrevID] = uint32(idx)
        }
    }

    // Compute sighash for each input using the mapped witness index.
    sigHashes := make([][]byte, len(vPkt.Inputs))
    for inputIdx := range vPkt.Inputs {
        vIn := vPkt.Inputs[inputIdx]

        wIdx, ok := witnessIndexByPrevID[vIn.PrevID]
        if !ok {
            return nil, fmt.Errorf("no witness index for input %d (prev_id=%s)",
                inputIdx, vIn.PrevID.String())
        }

        // Create input-specific virtual tx for this witness index.
        inputSpecificVirtualTx := asset.VirtualTxWithInput(
            virtualTx, newAsset.LockTime, newAsset.RelativeLockTime,
            wIdx, nil,
        )

        // Get the virtual prevOut for this input.
        prevOut, err := tapscript.InputAssetPrevOut(*vIn.Asset())
        if err != nil {
            return nil, fmt.Errorf("error getting prevOut for input %d: %w",
                inputIdx, err)
        }

        prevOutFetcher := txscript.NewCannedPrevOutputFetcher(
            prevOut.PkScript, prevOut.Value,
        )
        txSigHashes := txscript.NewTxSigHashes(
            inputSpecificVirtualTx, prevOutFetcher,
        )

        sigHash, err := txscript.CalcTaprootSignatureHash(
            txSigHashes, txscript.SigHashDefault,
            inputSpecificVirtualTx, 0, prevOutFetcher,
        )
        if err != nil {
            return nil, fmt.Errorf("error calculating sighash for input %d: %w",
                inputIdx, err)
        }

        sigHashes[inputIdx] = sigHash
    }

	return &pocketuniverserpc.ComputeSigHashResponse{
		Sighashes: sigHashes,
	}, nil
}

// ApplyExternalSignature applies an externally generated signature to a
// virtual PSBT.
func (r *rpcServer) ApplyExternalSignature(ctx context.Context,
	req *pocketuniverserpc.ApplyExternalSigRequest) (
	*pocketuniverserpc.ApplyExternalSigResponse, error) {

	vPkt, err := tappsbt.Decode(req.FundedPsbt)
	if err != nil {
		return nil, fmt.Errorf("error decoding packet: %w", err)
	}

	if len(vPkt.Inputs) == 0 {
		return nil, fmt.Errorf("packet has no inputs")
	}

	if len(req.Signatures) != len(vPkt.Inputs) {
		return nil, fmt.Errorf("signature count mismatch: got %d signatures for %d inputs",
			len(req.Signatures), len(vPkt.Inputs))
	}

	// Parse all signatures first
	sigs := make([]*schnorr.Signature, len(req.Signatures))
	for i, sigBytes := range req.Signatures {
		sig, err := schnorr.ParseSignature(sigBytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing signature %d: %w", i, err)
		}
		sigs[i] = sig
	}

	// Populate derivation info (same as SignVirtualPsbt)
	for _, input := range vPkt.Inputs {
		if len(input.Bip32Derivation) > 0 &&
			len(input.TaprootBip32Derivation) > 0 {
			continue
		}

		scriptKey := input.Asset().ScriptKey
		if scriptKey.TweakedScriptKey == nil {
			tweakedScriptKey, err := r.cfg.AssetWallet.FetchScriptKey(
				ctx, scriptKey.PubKey,
			)
			if err != nil {
				return nil, fmt.Errorf("error fetching "+
					"script key: %w", err)
			}
			scriptKey.TweakedScriptKey = tweakedScriptKey
		}

		derivation, trDerivation := tappsbt.Bip32DerivationFromKeyDesc(
			scriptKey.TweakedScriptKey.RawKey,
			r.cfg.ChainParams.HDCoinType,
		)
		input.Bip32Derivation = []*psbt.Bip32Derivation{derivation}
		input.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
			trDerivation,
		}
	}

	// Apply signature to each input
	for inputIdx, sig := range sigs {
		vIn := vPkt.Inputs[inputIdx]
		vIn.PInput.TaprootKeySpendSig = sig.Serialize()
	}

	inputs := vPkt.Inputs
	outputs := vPkt.Outputs

	isSplit, err := vPkt.HasSplitCommitment()
	if err != nil {
		return nil, err
	}

	newAsset := outputs[0].Asset
	var splitAssets []*commitment.SplitAsset
	if isSplit {
		splitOut, err := vPkt.SplitRootOutput()
		if err != nil {
			return nil, fmt.Errorf("no split root output: %w", err)
		}
		newAsset = splitOut.Asset

		splitAssets = make([]*commitment.SplitAsset, len(outputs))
		for idx := range outputs {
			splitAssets[idx] = &commitment.SplitAsset{
				Asset:       *outputs[idx].Asset,
				OutputIndex: outputs[idx].AnchorOutputIndex,
			}
			if outputs[idx].Type.IsSplitRoot() {
				splitAssets[idx].Asset = *outputs[idx].SplitAsset
			}
		}
	}

    // Build a map from PrevID to witness index for robust attachment.
    witnessIndexByPrevID := make(map[asset.PrevID]int)
    for idx := range newAsset.Witnesses() {
        w := newAsset.Witnesses()[idx]
        if w.PrevID != nil {
            witnessIndexByPrevID[*w.PrevID] = idx
        }
    }

    // Construct witnesses for all inputs and attach using the correct index.
    for inputIdx, sig := range sigs {
        vIn := vPkt.Inputs[inputIdx]
        witness := wire.TxWitness{sig.Serialize()}
        if vIn.SighashType != txscript.SigHashDefault {
            witness[0] = append(witness[0], byte(vIn.SighashType))
        }

        wIdx, ok := witnessIndexByPrevID[vIn.PrevID]
        if !ok {
            return nil, fmt.Errorf("no witness index for input %d (prev_id=%s)",
                inputIdx, vIn.PrevID.String())
        }

        if err := newAsset.UpdateTxWitness(wIdx, witness); err != nil {
            return nil, fmt.Errorf("attach witness failed for input %d: %w",
                inputIdx, err)
        }
    }

	// Validate the witness
	prevAssets := make(commitment.InputSet, len(inputs))
	for idx := range inputs {
		prevAssets[inputs[idx].PrevID] = inputs[idx].Asset()
	}

	err = r.cfg.AssetWallet.WitnessValidator().ValidateWitnesses(
		newAsset, splitAssets, prevAssets,
	)
	if err != nil {
		return nil, fmt.Errorf("witness validation failed: %w", err)
	}

	// Handle split commitment updates if needed
	if isSplit {
		for idx := range outputs {
			splitAsset := outputs[idx].Asset
			if outputs[idx].Type.IsSplitRoot() {
				splitAsset = outputs[idx].SplitAsset
			}
			splitCommitment := splitAsset.PrevWitnesses[0].SplitCommitment
			splitCommitment.RootAsset = *newAsset.Copy()
		}
	}

	// Build list of signed input indices
	signedInputs := make([]uint32, len(vPkt.Inputs))
	for i := range vPkt.Inputs {
		signedInputs[i] = uint32(i)
	}

	signedPsbt, err := tappsbt.Encode(vPkt)
	if err != nil {
		return nil, fmt.Errorf("error encoding signed packet: %w", err)
	}

	return &pocketuniverserpc.ApplyExternalSigResponse{
		SignedPsbt:   signedPsbt,
		SignedInputs: signedInputs,
	}, nil
}

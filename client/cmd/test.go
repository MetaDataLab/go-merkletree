/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/MetaDataLab/go-merkletree"
	"github.com/spf13/cobra"
)

// testCmd represents the mput command
var testCmd = &cobra.Command{
	Use:   "test",
	Short: "test a file's newMerkleTree/generateProof/verifyProof process",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		filePath, err := cmd.Flags().GetString("file")
		if err != nil {
			log.Panicf("get file Flag failed, %s", err.Error())
			return
		}

		chunkSize, err := cmd.Flags().GetUint64("chunkSize")
		if err != nil {
			log.Panicf("get chunkSize Flag failed, %s", err.Error())
			return
		}

		index, err := cmd.Flags().GetUint64("index")
		if err != nil {
			log.Panicf("get index Flag failed, %s", err.Error())
			return
		}
		fmt.Printf("parameters, filePath is %s, chunkSize is %d, index is %d\n", filePath, chunkSize, index)

		content, err := os.ReadFile(filePath)
		if err != nil {
			return
		}
		fmt.Printf("file content length is %d\n", len(content))

		hashType, err := merkletree.GetHashTypeFromCode(merkletree.KECCAK256)
		if err != nil {
			return
		}

		hashes := make([][]byte, 0)
		data := make([][]byte, 0)
		verifyData := make([]byte, 0)
		for i, chunkIndex := uint64(0), uint64(0); i < uint64(len(content)); i += chunkSize {
			end := i + chunkSize
			if end > uint64(len(content)) {
				end = uint64(len(content))
			}
			hashes = append(hashes, hashType.Hash(content[i:end]))
			if chunkIndex == index {
				verifyData = content[i:end]
			}
			data = append(data, content[i:end])
			chunkIndex++
		}
		fmt.Printf("len(verifyData)=%d\n", len(verifyData))
		for k := range data {
			fmt.Printf("data[%d] length is %d\n", k, len(data[k]))
		}

		tree, err := merkletree.NewTree(
			merkletree.WithData(data),
			merkletree.WithHashType(hashType),
		)
		if err != nil {
			return
		}
		rootHash := tree.Root()
		leaveHashes := tree.LeavesNodes()
		fmt.Printf("rootHash %v\n", rootHash)
		fmt.Printf("hashes %v\n", hashes)
		fmt.Printf("leaveHashes %v\n", leaveHashes)

		proof, _ := tree.GenerateIndexProof(index, 0)
		fmt.Printf("proof %v\n", proof)

		verified, err := merkletree.VerifyProofUsing(verifyData, false, proof, [][]byte{rootHash}, hashType)
		if err != nil {
			fmt.Printf("VerifyProofUsing failed, err: %s\n", err.Error())
		}
		if !verified {
			fmt.Printf("VerifyProofUsing result is %v, %v !!!\n", verified, "\U0001F622")
		} else {
			fmt.Printf("VerifyProofUsing result is %v, %v great\n", verified, "\U0001F60A")
		}
	},
}

func init() {
	rootCmd.AddCommand(testCmd)
	testCmd.Flags().StringP("file", "f", "", "file to upload")
	testCmd.Flags().Uint64P("chunkSize", "c", 0, "chunk size")
	testCmd.Flags().Uint64P("index", "i", 0, "which chunk to verify")
}

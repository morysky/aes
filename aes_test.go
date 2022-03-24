package aes

import (
	"testing"
)

const Key string = "hugo"

func TestEncrypt(t *testing.T) {
	testCases := []struct {
		desc   string
		input  string
		output string
	}{
		{
			desc:   "加密",
			input:  "ABC",
			output: "QYqJdNQIZ5j5q4iqIhuAsg==",
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			output, _ := Encrypt(tC.input, Key)
			if output != tC.output {
				t.Errorf("Encrypt(%s) = %s; excepted %s", tC.input, output, tC.output)
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	testCases := []struct {
		desc   string
		input  string
		output string
	}{
		{
			desc:   "解密",
			input:  "QYqJdNQIZ5j5q4iqIhuAsg==",
			output: "ABC",
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			output, _ := Decrypt(tC.input, Key)
			if output != tC.output {
				t.Errorf("Decrypt(%s) = %s; excepted %s", tC.input, output, tC.output)
			}
		})
	}
}

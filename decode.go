/*
Dec is a utility to decode base64 encoded strings with a single byte XOR
See: https://s1.ai/r2pipe

Usage:
      From r2 prompt, seek to address of encoded string or pass strings when calling
      Example 1
      >	#!pipe <path to binary>
      Example 2	
      > #!pipe <path to binary> @@=`izz~==[2]`

*/

package main                                            

import (
 
  "fmt"
  "github.com/radareorg/r2pipe-go"
)

var r2p, _ = r2pipe.NewPipe("") 			// Declare r2p as a global so we can use it throughout our functions

func check(err error) {
     if err != nil {
	panic(err)
     }
}

func decryptStrAtLoc(loc string, key string) {
     bytes := fmt.Sprintf("ps @ %s", loc) 	      // 'ps' = return bytes at current address as string  
     str, err := r2p.Cmd(bytes)
     check(err)
     decodeCmd := fmt.Sprintf("!rxorb -b %s %s > /tmp/rxorb", key, str)
     r2p.Cmd(decodeCmd)
} 

func writeCommentAtLoc(loc string) {
     readCmd := fmt.Sprintf("CCu `!cat -v /tmp/rxorb | sed 's/\\(.*\\)/\"\\1\"/g'` @ %s", loc)    
     r2p.Cmd(readCmd)                                 // read the decoded string back into r2 and write as a comment
}

func printCommentAtLoc(loc string) {
     pdCmd := fmt.Sprintf("pd 1 @ %s", loc)           // print out each address with the decoded string
     pdStr, _ := r2p.Cmd(pdCmd)
     fmt.Println(pdStr)
}

func main() {
     key := "0x30"				      // todo: supply the key as an arg
     addr, err := r2p.Cmd("s") 			      // 's' = return current address
     check(err)
	 
     decryptStrAtLoc(addr, key)
     writeCommentAtLoc(addr)
     printCommentAtLoc(addr)

     delCmd := fmt.Sprintf("!rm /tmp/rxorb")          // clean up the temp file
     r2p.Cmd(delCmd)
     if err != nil {
     	 fmt.Println(err)
     }
     defer r2p.Close()
}

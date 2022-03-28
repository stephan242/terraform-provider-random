resource "random_uuid" "test" {
}


resource "random_ssh_keypair" "test2" {
  keytype = "ecdsa"
  //keytype = "ed25519"
}

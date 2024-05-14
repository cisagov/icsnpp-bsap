# BSAP IP Signature
# Payload Signature by Christian Weelborg
# Last modified May 2nd, 2024
# First byte is Message Type (either 0e or 16)
# Second byte is always 00
# Third byte is the num_messages and is typically 01 but not always
# Fourth byte is always 00
# Fifth byte is the Message Function (00, 01, 05, 06, 84, 86)
# Sixth byte is always 00

signature dpd_bsap {
    ip-proto == udp
    payload /(\x0e|\x16)\x00(?s:.)\x00(\x00|\x01|\x05|\x06|\x84|\x86)\x00/
    enable "BSAP"
}

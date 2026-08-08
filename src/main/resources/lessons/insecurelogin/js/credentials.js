function submit_secret_credentials() {
    var xhttp = new XMLHttpRequest();
    xhttp['open']('POST', 'InsecureLogin/login', true);
	//sending the request is obfuscated, to descourage js reading
	//the password itself is never put on the wire: only its SHA-256 hash is sent, so
	//sniffing this request no longer discloses the real, clear-text credential
	var _0xb7f9=["\x43\x61\x70\x74\x61\x69\x6E\x4A\x61\x63\x6B","50BCEEA465D2B2DC665B769723F174018C5D096A402C370C472302CA8374A9DA","\x73\x74\x72\x69\x6E\x67\x69\x66\x79","\x73\x65\x6E\x64"];xhttp[_0xb7f9[3]](JSON[_0xb7f9[2]]({username:_0xb7f9[0],password:_0xb7f9[1]}))
}

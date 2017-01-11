package com.erith.commontools.security.xmlsignature;

import java.security.PrivateKey;
import java.security.PublicKey;

import javax.xml.crypto.dsig.keyinfo.KeyInfo;

public interface PrivateKeyProvider {

	KeyInfo loadKeyInfo();

	PrivateKey loadPrivateKey();

	PublicKey loadPublicKey();
}

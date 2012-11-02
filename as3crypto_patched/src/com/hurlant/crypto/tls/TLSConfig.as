/**
 * TLSConfig
 * 
 * A set of configuration parameters for use by a TLSSocket or a TLSEngine.
 * Most parameters are optional and will be set to appropriate default values for most use.
 * 
 * Copyright (c) 2007 Henri Torgemane
 * 
 * See LICENSE.txt for full license information.
 */
package com.hurlant.crypto.tls {
	import com.hurlant.crypto.cert.MozillaRootCertificates;
	import com.hurlant.crypto.cert.X509Certificate;
	import com.hurlant.crypto.cert.X509CertificateCollection;
	import com.hurlant.crypto.hash.MD5;
	import com.hurlant.crypto.rsa.RSAKey;
	import com.hurlant.util.Hex;
	import com.hurlant.util.der.PEM;
	
	import flash.utils.ByteArray;
	
	public class TLSConfig {
		public var entity:uint; // SERVER | CLIENT
		
		public var certificate:ByteArray;
		public var privateKey:RSAKey;
		
		public var cipherSuites:Array;
		
		public var compressions:Array;
		public var ignoreCommonNameMismatch:Boolean = false;
		public var trustExpiredCertificates:Boolean = false;
		public var trustAllCertificates:Boolean = false;
		public var trustSelfSignedCertificates:Boolean = false;
		public var promptUserForAcceptCert:Boolean = false;
		public var CAStore:X509CertificateCollection;
		public var localKeyStore:X509CertificateCollection;
		public var version:uint;
		
		//карта md5 доверенных сертификатов
		public var trustedCertificates:Object = {};
		
		public function TLSConfig(	entity:uint, cipherSuites:Array = null, compressions:Array = null, 
									certificate:ByteArray = null, privateKey:RSAKey = null, CAStore:X509CertificateCollection = null, ver:uint = 0x00, trustedCertificates:X509CertificateCollection = null ) {
			this.entity = entity;
			this.cipherSuites = cipherSuites;
			this.compressions = compressions;
			this.certificate = certificate;
			this.privateKey = privateKey;
			this.CAStore = CAStore;
			this.version = ver;
			// default settings.
			if (cipherSuites==null) {
				this.cipherSuites = CipherSuites.getDefaultSuites();
			}
			if (compressions==null) {
				this.compressions = [TLSSecurityParameters.COMPRESSION_NULL];
			}
			
			if (CAStore==null) {
				this.CAStore = new MozillaRootCertificates;
			}
			
			if (ver==0x00) {
				// Default to TLS
				this.version = TLSSecurityParameters.PROTOCOL_VERSION;
			} 
		}
		
		public function setPEMCertificate(cert:String, key:String = null):void {
			if (key == null) {
				key = cert; // for folks who like to concat those two in one file.
			}
			certificate = PEM.readCertIntoArray(cert);
			privateKey = PEM.readRSAPrivateKey(key);
		}
		
		/**
		 * Add own your own trusted certificate
		 * @param cert A ByteArray object containing a DER-encoded X.509 digital certificate.
		 */
		public function addTrustedCertificate(cert:ByteArray):void
		{
			var md5:String = Hex.fromArray(new MD5().hash(cert));
			trustedCertificates[md5] = true;
		}
		
		/**
		 * Check whether the certificate is marked as trusted
		 * @param cert
		 * @return
		 */
		public function isTrustedCertificate(cert:X509Certificate):Boolean
		{
			var md5:String = cert.md5;
			return trustedCertificates[md5];
		}
	}
}
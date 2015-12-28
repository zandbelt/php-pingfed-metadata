<?php
/***************************************************************************
 * Copyright (C) 2014-2015 Ping Identity Corporation
* All rights reserved.
*
* The contents of this file are the property of Ping Identity Corporation.
* For further information please contact:
*
*      Ping Identity Corporation
*      1099 18th St Suite 2950
*      Denver, CO 80202
*      303.468.2900
*      http://www.pingidentity.com
*
* DISCLAIMER OF WARRANTIES:
*
* THE SOFTWARE PROVIDED HEREUNDER IS PROVIDED ON AN "AS IS" BASIS, WITHOUT
* ANY WARRANTIES OR REPRESENTATIONS EXPRESS, IMPLIED OR STATUTORY; INCLUDING,
* WITHOUT LIMITATION, WARRANTIES OF QUALITY, PERFORMANCE, NONINFRINGEMENT,
* MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  NOR ARE THERE ANY
* WARRANTIES CREATED BY A COURSE OR DEALING, COURSE OF PERFORMANCE OR TRADE
* USAGE.  FURTHERMORE, THERE ARE NO WARRANTIES THAT THE SOFTWARE WILL MEET
* YOUR NEEDS OR BE FREE FROM ERRORS, OR THAT THE OPERATION OF THE SOFTWARE
* WILL BE UNINTERRUPTED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
* CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
* EXEMPLARY, OR CONSEQUENTIAL DAMAGES HOWEVER CAUSED AND ON ANY THEORY OF
* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
		* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**************************************************************************/
/*
* @Author: Hans Zandbelt - hzandbelt@pingidentity.com
*
**************************************************************************/

/*
 * configuration parameters
 */
$cfg = array(
	/* the URL (may be file://) to the federation metadata that contains the EntitiesDescriptor */
#	'remote-metadata-url' => 'http://md.incommon.org/InCommon/InCommon-metadata.xml',
	'remote-metadata-url' => 'file://InCommon-metadata.xml',
	'stats' => array(
			'sp' => array(
					'number-of-certs' => array(
							'signing' => array(			
							),
							'encryption' => array(			
							)
					),
					'expired-certs' => array(
							'signing' => array(
									'all-expired' => array(
										'count' => 0,
										'entities' => array()											
									),
									'single-primary-expired' => array(
										'count' => 0,
										'entities' => array()											
									),
									'two-expired' => array(
										'count' => 0,
										'entities' => array()											
									),
							),
							'encryption' => array(
									'all-expired' => array(
											'count' => 0,
											'entities' => array()
									),
									'single-primary-expired' => array(
											'count' => 0,
											'entities' => array()
									),
									'two-expired' => array(
											'count' => 0,
											'entities' => array()
									),
							)
					)
			),
			'idp' => array(
					'number-of-certs' => array(
							'signing' => array(			
							),
							'encryption' => array(			
							)
					),
					'expired-certs' => array(
							'signing' => array(
									'all-expired' => array(
										'count' => 0,
										'entities' => array()											
									),
									'single-primary-expired' => array(
										'count' => 0,
										'entities' => array()											
									),
									'two-expired' => array(
										'count' => 0,
										'entities' => array()											
									),
							),
							'encryption' => array(
									'all-expired' => array(
										'count' => 0,
										'entities' => array()											
									),
									'single-primary-expired' => array(
										'count' => 0,
										'entities' => array()											
									),
									'two-expired' => array(
										'count' => 0,
										'entities' => array()											
									),
							)
					)
			)
	)
);

/*
 * perform HTTP call (GET/POST/PUT) and return results
 */
function http_exec($url, $method = NULL, $data = NULL, $username = NULL, $password = NULL, $verify_peer = 1, $verify_host = 1) {
	$ch = curl_init();

	#curl_setopt($ch, CURLOPT_VERBOSE, 1);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $verify_peer);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $verify_host);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

	if ( ($username != NULL) and ($password != NULL) ) {
		curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC ) ;
		curl_setopt($ch, CURLOPT_USERPWD, $username . ':' . $password);
	}

	curl_setopt($ch, CURLOPT_URL, $url);

	$headers = array('X-XSRF-Header: dummy');
	if ($method == "POST") {
		curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
	} else if ($method == "PUT") {
		$headers[] = 'Content-type: application/json';
		curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PUT");
		curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
	}
	curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

	$result = curl_exec($ch);
	print_r(curl_error($ch));
	curl_close($ch);
	
	return $result;
}

/*
 * Calculate the SHA1 fingerprint for a PEM-encoded X.509 certificate.
 */
function sha1_thumbprint($cert) {
	$file = preg_replace('/\-+BEGIN CERTIFICATE\-+/','',$cert);
	$file = preg_replace('/\-+END CERTIFICATE\-+/','',$cert);
	$file = trim($cert);
	$file = str_replace( array("\n\r","\n","\r"), '', $cert);
	$bin = base64_decode($cert);
	return sha1($bin);
}

/*
 * Extract a PEM-encoded X.509 certificate from an XML KeyDescriptor element.
 */
function keydescriptor_certifcate_get($xpath, $key_desc) {
	$cert = $xpath->query('ds:KeyInfo/ds:X509Data/ds:X509Certificate', $key_desc);
	$cert = "-----BEGIN CERTIFICATE-----\n" . trim($cert->item(0)->textContent) . "\n-----END CERTIFICATE-----\n";
	return $cert;
}

/*
 * Retrieve XML metadata from a URL and parse out the EntitiesDescriptor element.
 */
function xml_retrieve_entities_descriptor($metadata_url) {
	$metadata = http_exec($metadata_url, "GET", NULL, NULL, NULL, 0, 0, 0);
	$doc = new DOMDocument(true);
	$doc->loadXML($metadata);
	$xpath = new DOMXpath($doc);
	$xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
	$xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
	return array($xpath, $xpath->query('/md:EntitiesDescriptor', $doc->documentElement));
}

/*
 * Return the first and second signing certificates in the list of KeyDescriptors in the SSODescriptor.
 */
function metadata_get_signing_certs($xpath, $sso_desc, $req_use) {
	$primary_xml = NULL;
	$secondary_xml = NULL;
	$nr = 0;
	foreach ($xpath->query('md:KeyDescriptor', $sso_desc->item(0)) as $key_desc) {
		$use = $key_desc->getAttribute('use');
		if ( ($use == NULL) || ($use == $req_use) ) {
			if ($primary_xml == NULL) {
				$primary_xml = keydescriptor_certifcate_get($xpath, $key_desc);
			} else if ($secondary_xml == NULL) {
				$secondary_xml = keydescriptor_certifcate_get($xpath, $key_desc);
			}
			$nr++;
		}
	}
	return array($primary_xml, $secondary_xml, $nr);
}
/*
 * Process an IDPSSODescriptor
 */
function xml_process_sso_descriptor(&$cfg, $xpath, $sso_desc, $type, $use, $entityid, $name) {
	list($primary_xml, $secondary_xml, $nr) = metadata_get_signing_certs($xpath, $sso_desc, $use);
	if ($primary_xml == NULL) {
		#echo " # 1st is NULL\n";
	}
	$cfg['stats'][$type]['number-of-certs'][$use][$nr]++;

	$no_valid_cert = true;
	if ($primary_xml != NULL) {
		$primary = openssl_x509_parse($primary_xml);
		if ($primary['validTo_time_t'] < time()) {
			$cfg['stats'][$type]['expired-certs'][$use]['primary']++;
			#if (($type == 'idp') && ($use == "signing")) echo " # primary signing cert expired for IDP: ". $entityid . "\n";
		} else {
			$no_valid_cert = false;
		}
	}
	
	if ($secondary_xml != NULL) {
		$secondary = openssl_x509_parse($secondary_xml);
		if ($secondary['validTo_time_t'] < time()) {
			$cfg['stats'][$type]['expired-certs'][$use]['secondary']++;
		} else {
			$no_valid_cert = false;
		}
	}
	
	#if ($no_valid_cert) echo " # no valid " . $use . " cert for " . $type . ": ". $entityid . "\n";

	if (($no_valid_cert) && (($primary_xml != NULL) || ($secondary_xml != NULL))) {
		$cfg['stats'][$type]['expired-certs'][$use]['all-expired']['count']++;
		$cfg['stats'][$type]['expired-certs'][$use]['all-expired']['entities'][] = $entityid . " " . $name;
	}
	
	if (($no_valid_cert) && ($primary_xml != NULL) && ($secondary_xml != NULL)) {
		$cfg['stats'][$type]['expired-certs'][$use]['two-expired']['count']++;
		$cfg['stats'][$type]['expired-certs'][$use]['two-expired']['entities'][] = $entityid . " " . $name;
	}

	if (($no_valid_cert) && ($primary_xml != NULL) && ($secondary_xml == NULL)) {
		$cfg['stats'][$type]['expired-certs'][$use]['single-primary-expired']['count']++;
		$cfg['stats'][$type]['expired-certs'][$use]['single-primary-expired']['entities'][] = $entityid . " " . $name;
	}
	
	#if ($no_valid_cert && ($type == 'idp') && ($use == "signing")) echo " # no valid signing cert expired for IDP: ". $entityid . "\n";
	
	return $nr;
}

/*
 * process an EntitiesDescriptor
 */
function xml_process_entities_descriptor(&$cfg, $xpath, $descriptor) {
	/* loop over the EntityDescriptor's embedded in this EntitiesDescriptor */
	foreach ($xpath->query('md:EntityDescriptor', $descriptor->item(0)) as $desc) {
		$entityid = $desc->getAttribute('entityID');
		$org = $xpath->query('md:Organization/md:OrganizationName', $desc);
		$name = ($org->length > 0) ? $org->item(0)->textContent : $entityid;
		
		/* check if this EntityDescriptor is an IDP */
		$idp_desc = $xpath->query('md:IDPSSODescriptor', $desc);
		if ($idp_desc->length > 0) {
			#echo " # processing IDP: " . $entityid . "\n";
			$nr = xml_process_sso_descriptor($cfg, $xpath, $idp_desc, 'idp', 'signing', $entityid, $name);
			if ($nr > 2) {
				echo "\n # more than 2 signing certs IDP: " . $entityid . "\n\n";
				#exit;
			}
			$nr = xml_process_sso_descriptor($cfg, $xpath, $idp_desc, 'idp', 'encryption', $entityid, $name);
			if ($nr > 2) {
				echo "\n # more than 2 encryption certs IDP: " . $entityid . "\n\n";
				#exit;
			}
		}
		
		$sp_desc = $xpath->query('md:SPSSODescriptor', $desc);
		if ($sp_desc->length > 0) {
			#echo " # processing SP: " . $entityid . "\n";
			$nr = xml_process_sso_descriptor($cfg, $xpath, $sp_desc, 'sp', 'signing', $entityid, $name);
			if ($nr > 2) {
				echo "\n # more than 2 signing certs SP: " . $entityid . "\n\n";
				exit;
			}
			$nr = xml_process_sso_descriptor($cfg, $xpath, $sp_desc, 'sp', 'encryption', $entityid, $name);
			if ($nr > 2) {
				echo "\n # more than 2 encryption certs SP: " . $entityid . "\n\n";
				exit;
			}
		}
	}
}

/*
 * Retrieve the EntitiesDescriptor from the remote location (may be URL to a file on disk).
 */
list($xpath, $descriptor) = xml_retrieve_entities_descriptor($cfg['remote-metadata-url']);

/*
 * Process/compare the connection information.
 */
xml_process_entities_descriptor($cfg, $xpath, $descriptor);

print_r($cfg);
?>

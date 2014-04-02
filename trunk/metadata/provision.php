<?php
/***************************************************************************
 * Copyright (C) 2011-2014 Ping Identity Corporation
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
 * This script imports SAML 2.0/SAML 1.1 connections defined in SAML 2.0
 * metadata documents into PingFederate >=7.1.3 by augmenting the metadata document
 * with PingFederate connection specific configuration settings and upload
 * it using PingFederate's Connection Manager webservice API.
 * 
 * Features:
 * 
 * - handles both documents with an EntitiesDescriptor (containing multiple embedded
 *   EntityDescriptor's) and "flat" files with one or more EntityDescriptor's
 *   
 * - augments the SAML 2.0 metadata with PingFederate specific configuration
 *   extensions:
 *   - friendly connection name
 *   - SP/IDP adapter instance
 *   - attribute contract fulfilment and attribute mappings
 *   - signing key
 *   - allowable bindings (Redirect,POST,SOAP,Artifact)
 *   - dummy SOAP backchannel credentials (see below)
 *   
 * - will generate unique "friendly connection names" based organization info
 *   embedded in the metadata document, prefixed with a "[P] " to distinguish
 *   it visually in the admin console from manually configured connections and
 *   if necessary postfixed with a sequence number to avoid clashes
 * 
 * - (optional) metadata signature verification against a pre-configured X.509 certificate
 *   
 * - when an SPSSODescriptor or IDPSSODescriptor for an entity contains both
 *   SAML 2.0 and SAML 1.1 connection info (protocolEnumeration), SAML 2.0
 *   connection info will be preferred as PingFederate cannot configure both
 *   at the same time for a single entity
 * 
 * - include and/or excludes specific entities based on their entity identifier
 *   for testing purposes or for importing only a subset of the complete list of
 *   entities
 *   
 * Known Issues:
 * 
 *  - signature verification on a very large set of metadata may take very long (many minutes).
 *    This is the case for the InCommon and UK Access Federation metadata.
 *    
 *  - some federations (in fact maybe only UK Access Federation by now) may still contain IDPs
 *    that base their signing key material on the now deprecated method of named keys that refer
 *    to keys issued by an root CA whose certificate is embedded in the metadata outside of
 *    the EntityDescriptor instead of embedding the actual (possibly self-signed) signing
 *    certificate in the EntityDescriptor
 *    
 *  - The current implementation of saveConnection does not do SSL server certificate validation.
 *   
 * Shortcuts:
 * 
 * - on all SOAP backchannel calls, both incoming and outgoing, basic authentication
 *   is configured with a default username [=urlencode(<role>:<entityid>)] and password ("Changeme1") is
 *   configured; this is necessarily a placeholder only because these credentials
 *   info needs to be negiotated with peer entities out-of-band; one could extend
 *   this script with the negotiated per-entity credentials for this purpose
 *
 * TBD:
 * 
 * - speed up canonicalization
 * - support for DataSources
 * - support for nested EntitiesDescriptor's (?)
 * - the script is self-contained now but it may be better to rely on libraries for:
 *   - soap (SoapClient), including SSL server certificate validation
 *   - metatata url retrieval (CURL)
 *   - signature verification (xmlseclib)
 *   
 * Notes:
 * 
 *  - Tested to work against InCommon, UK Access Federation and SURFfederatie metadata.
 * 
 *  - Custom extensions in existing metadata will be stripped out: PingFederate would choke on
 *    it and would not be able to support those extensions (eg. shib scope) anyway.
 * 
 *  - Import of a large number of entities may take a considerable time
 *    (eg. 8.5 mins for 886 entities on a MacBook Air 1.7 GHz Intel Core i5).
 *
 *  - enable the Connection Management service (username/password to be configured in this
 *    file, and enable both the SAML 2.0 and 1.1 roles for IDP/SP.
 *
 *  - Be sure to switch off auto-connection-validation in the System Options of the Server
 *    Settings of the PingFederate management console to avoid an unusably slow console
 *    when dealing with a large number of connections.
 *  
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 *
 **************************************************************************/

$config = array(

	###################################################
	# MODIFY SETTINGS BELOW TO MATCH YOUR ENVIRONMENT #
	###################################################

	// remote metadata url
	'metadata-url' => 'http://md.incommon.org/InCommon/InCommon-metadata.xml',
	// alternatively download it to disk first, then refer to it as a file on disk (better performance in testing...)
#	'metadata-url' => 'InCommon-metadata.xml',

	// path to certificate with he public key to verify the metadata that is downloaded
#	'metadata-certificate' => 'inc-md-cert.pem',

#	'metadata-url' => 'http://metadata.ukfederation.org.uk/ukfederation-metadata.xml',
#	'metadata-url' => 'ukfederation-metadata.xml',
#	'metadata-certificate' => 'ukfederation-metadata.pem',

	// the URL to the connection management API of your PingFederate server
	'connection-management-url' => 'https://localhost:9999/pf-mgmt-ws/ws/ConnectionMigrationMgr',
	// the username for the connection management API as configured in the API settings on the PingFederate admin console
	'user' => 'heuristics',
	// the password for the connection management API as configured in the API settings on the PingFederate admin console
	'password' => 'Changeme1',

	// the MD5 fingerprint of the private key that you want to use to sign outgoing SAML messages
	// copy this from the certificate management detail screen in the "Digital Signing & XML Decryption Keys & Certificates" section
	'signing-key-fingerprint' => '13E192DEF158C6185C41D0DDE954F0AB',

	// settings for the IDP and SP adapter that gets configured for the IDP and SP connections respectively
	'adapter' => array(
		// IDP adapter settings
		'idp' => array(
			// IDP adapter instance identifier
			'instance' => 'idpadapter',
			// attribute map: assertion-name => adapter-name; default value is to map the SAML subject in to the attribute value
			'attribute-map' => array(
				// TODO: extend to non-adapter attribute soruces, ie. datasources				
				'SAML_SUBJECT' => 'subject',
				'urn:mace:dir:attribute-def:givenName' => 'subject',
				'urn:mace:dir:attribute-def:mail' => 'subject',
				'urn:mace:dir:attribute-def:sn' => 'subject',				
			),
		),
		// SP adapter settings
		'sp' => array(
			// IDP adapter instance identifier
			'instance' => 'spadapter',
			// attribute map: adapter-name => assertion-name
			'attribute-map' => array(
				'subject' => 'SAML_SUBJECT',
				'email address' => 'SAML_SUBJECT',
				'member status' => 'SAML_SUBJECT',
				'userid' => 'SAML_SUBJECT',
				'name' => 'SAML_SUBJECT',
			),
		),
	),

	#######################################
	# PROBABLY DON'T NEED TO MODIFY BELOW #
	#######################################
	
	# allowable bindings, if endpoints exist
	'bindings' => array('Redirect' => 'true', 'POST' => 'true', 'SOAP' => 'true', 'Artifact' => 'true'),

	// for SAML 1.1; TODO: to be determined out-of-band on a per-partner basis, if needed (as opposed to using RelayState)
	'dummy-default-targetresource' => 'http://dummy',

	// needed for Artifact SOAP backchannel profile (incoming, ao. for SAML 1.1), and for Attribute Query (outgoing)
	// TODO: one does not normally use the same password for all connections, for sure not outgoing and incoming, but this is to be determined out-of-band on a per-partner basis!
	'basic-auth-password' => 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiM2ZmNE9NRTBSMiIsInZlcnNpb24iOiI3LjEuMzAwLjUifQ..y64VqbQhweRjOsXcXmvOmg.UDqKqY0p3C7LuuT0WXn0fw.tLbC3aMwcA7h_5z7aOVKyg',

	# choose SAML 2.0 over SAML 1.1 (and Shibboleth 1.0) if both listed in protocolEnumeration
	# by default PF will take SAML 1.1 (or perhaps just the first in the enumeration list)
	'preferred-protocol' => 'urn:oasis:names:tc:SAML:2.0:protocol',
	
	# include or exclude entities: for testing purposes or to restrict the number of imported entities

	# listing an entry in "exclude" means that its connection information will not be processed
	'exclude' => array(
	),
	# listing an entry in "include" means that all entities not listed here will be ignored
	'include' => array(
#		'urn:mace:eduserv.org.uk:athens:federation:beta',
#		'https://carmenwiki.osu.edu/shibboleth',
	),
	
	# don't touch: for internal state keeping purposes to generate unique friendly names
	'duplicate-name-fix' => array('sp' => array(), 'idp' => array()),
);

define('PF_SAVE_CONN_RSP_OK',	'<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://www.w3.org/2003/05/soap-envelope" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body><saveConnectionResponse soapenv:encodingStyle="http://www.w3.org/2003/05/soap-encoding"/></soapenv:Body></soapenv:Envelope>');
define('PF_DELETE_CONN_RSP_OK',	'<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://www.w3.org/2003/05/soap-envelope" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body><deleteConnectionResponse soapenv:encodingStyle="http://www.w3.org/2003/05/soap-encoding"/></soapenv:Body></soapenv:Envelope>');

/**
 * Verify the signature on an XML document using a public key.
 * 
 * @param DOMDocument $doc the XML dom document
 * @param string $cert the PEM formatted certificate data
 */
function xml_sig_verify($doc, $cert) {
	$result = true;
	$xp = new DomXPath($doc);
	$xp->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
	$signature = $xp->query(".//ds:Signature", $doc);
	// make sure we remove the signature, even if we don't want to check it to avoid confusing PingFederate
	if ($signature->length > 0) {
		$signature = $signature->item(0);
		$signatureValue = $xp->query(".//ds:SignatureValue", $signature)->item(0)->textContent;
		$digestValue = $xp->query(".//ds:SignedInfo/ds:Reference/ds:DigestValue", $signature)->item(0)->textContent;
		$signedInfo = $xp->query(".//ds:SignedInfo", $signature)->item(0)->C14N(true, false);
		$signature->parentNode->removeChild($signature);
		if ($cert !== NULL) {
			echo " # INFO: canonicalizing metadata; this may take very long  if the document is large (many minutes)...\n";
			$canonicalXml = $doc->documentElement->C14N(true, false);
			echo " # INFO: canonicalizing metadata finished OK!\n";
			$digestMatches = (base64_encode(sha1($canonicalXml, true)) == $digestValue);
			$result = $digestMatches ? (openssl_verify($signedInfo, base64_decode($signatureValue), $cert) === 1) : false;
		} else {
			echo " # WARN: signature not verified but removed.\n";
		}
	} else if ($cert !== NULL) {
		echo " # WARN: no signature found in metadata.\n";
		$result = false;
	}
	return $result;
}

/**
 * Retrieve a SAML 2.0 metadata document from the specified location and optionally verify the signature on it.
 * 
 * @param string $url the URL where the metadata document should be retrieved from
 * @param string $cert the public key against which the document's signature should be verified, or NULL if it should not be verified
 */
function metadata_retrieve_and_verify($url, $cert = NULL) {
	$metadata = file_get_contents($url);
	$doc = new DOMDocument(true);
	$doc->loadXML($metadata);
	$result = xml_sig_verify($doc, $cert);
	if ($result !== true) {
		echo " # ERROR: signature verification failed!\n";
		exit;
	}
	if ($cert !== NULL) echo " # INFO: signature verification OK.\n";
	return $doc;
}

/**
 * Do a SOAP call to a specified SOAP endpoint, using HTTP basic auth.
 * 
 * @param string $url the SOAP endpoint
 * @param string $header the SOAP header payload
 * @param string $body the SOAP body payload
 * @param string $user the username for HTTP basic auth
 * @param string $password the password for HTTP basic auth
 */
function soap_call_basic_auth($url,  $header, $body, $user, $password) {
	$request = <<<XML
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>$header</s:Header>
  <s:Body>$body</s:Body>
</s:Envelope>	
XML;
	$cred = sprintf('Authorization: Basic %s', base64_encode("$user:$password"));
	$opts = array('http' => array(
		'method'  => 'POST',
		'header'  => "Content-Type: application/soap+xml; charset=UTF-8\r\nsoapAction: " . $url . "\r\n" . $cred,
        'content' => $request
		),
    );
	$context  = stream_context_create($opts);
	$result = file_get_contents($url, false, $context);
	return $result;
}

/**
 * Save connection info to PingFederate.
 *
 * @param array $cfg the global configuration settings
 * @param DOMDocument $doc the metadata dom document
 * @param DOMElement $desc the EntityDescriptor element with the connection info
 * @param string $entityid the Entity identifier of the connection
 */
function pf_connection_save(&$cfg, $doc, $desc, $entityid) {
	$doc->formatOutput = true;
	$body = '<saveConnection><param0>' . htmlspecialchars($doc->saveXML($desc->cloneNode(true))) . '</param0><param1>true</param1></saveConnection>';	
	$result = soap_call_basic_auth($cfg['connection-management-url'], '', $body, $cfg['user'], $cfg['password']);
	if ($result !== PF_SAVE_CONN_RSP_OK) {
		echo "\n$result\n";
		echo "\n # ERROR: uploading the connection for \"$entityid\" failed.\n";		
		print_r($cfg);
		exit;
	}
}

/**
 * Get connection info from PingFederate.
 *
 * @param array $cfg the global configuration settings
 * @param string $entityid the Entity identifier of the connection
 */
function pf_connection_get(&$cfg, $entityid, $type) {
	$body = '<getConnection><param0>' . htmlspecialchars($entityid) . '</param0><param1>' . $type . '</param1></getConnection>';	
	return soap_call_basic_auth($cfg['connection-management-url'], '', $body, $cfg['user'], $cfg['password']);
}

/**
 * Create PingFederate specific Extensions to the SAML 2.0 metadata of an entity, based on the global configuration settings.
 * 
 * @param array $cfg the global configuration settings
 * @param DOMDocument $doc the metadata dom document
 * @param DOMXPath $xpath an xpath expression evaluator instance on the dom document
 * @param DOMElement $desc the SP/IDP SSO entity descriptor
 * @param string $entityid the entity identifier
 */
function pf_connection_create_extensions_role(&$cfg, $doc, $xpath, $desc, $entityid) {
		
	$extensions = $xpath->query('md:Extensions', $desc);
	if ($extensions->length > 0) {
		echo " # WARN: ignoring unsupported role extensions for entity \"$entityid\":\n";
		echo $doc->saveXML($extensions->item(0)) . "\n\n";
		$desc->removeChild($extensions->item(0));
	}

	$extensions = $doc->createElementNS('urn:oasis:names:tc:SAML:2.0:metadata', 'md:Extensions');
	$desc->insertBefore($extensions, $desc->firstChild);
	$role_ext = $doc->createElement('urn:RoleExtension');
	
	$bindings = $cfg['bindings'];
	$artifact = $xpath->query('ArtifactResolutionService', $desc);
	if ($artifact->length == 0) $bindings['Artifact'] = 'false';
	$inc_bind = $doc->createElement('urn:IncomingBindings');
	foreach ($bindings as $key => $value) $inc_bind->setAttribute($key, $value);	
	$role_ext->appendChild($inc_bind);

	$enabled_profiles = $doc->createElement('urn:EnabledProfiles');
	$enabled_profiles->setAttribute('SPInitiatedSSO', 'true');
	$enabled_profiles->setAttribute('IDPInitiatedSSO', 'true');
	$enabled_profiles->setAttribute('SPInitiatedSLO', 'false');
	$enabled_profiles->setAttribute('IDPInitiatedSLO', 'false');
	$role_ext->appendChild($enabled_profiles);

	$extensions->appendChild($role_ext);
	
	return $role_ext;
}

/**
 * Create an IDP connection in PingFederate.
 * 
 * @param array $cfg the global configuration
 * @param DOMDocument $doc the metadata dom document
 * @param DOMXPath $xpath an xpath evaluator instance on the dom document
 * @param DOMElement $desc an EntityDescriptor element
 * @param DOMElement $idp_desc an IDPSSODescriptor element
 * @param string $entityid the entity identifier of the IDP
 */
function pf_connection_create_idp(&$cfg, $doc, $xpath, $desc, $idp_desc, $entityid) {
	
	$role_ext = pf_connection_create_extensions_role($cfg, $doc, $xpath, $idp_desc, $entityid);
	
	$idp = $doc->createElement('urn:IDP');
	$mapping = $doc->createElement('urn:TargetAttributeMapping');

	$mapping->setAttribute('AdapterInstanceId', $cfg['adapter']['sp']['instance']);
	foreach ($cfg['adapter']['sp']['attribute-map'] as $key => $value) {
		$map = $doc->createElement('urn:AttributeMap');
		$map->setAttribute('Value', $value);
		$map->setAttribute('Type', 'Assertion');
		$map->setAttribute('Name', $key);
		$mapping->appendChild($map);
	}
	$idp->appendChild($mapping);
	$role_ext->appendChild($idp);
	
	pf_connection_save($cfg, $doc, $desc, $entityid);
}

/**
 * Create a SP connection in PingFederate.
 * 
 * @param array $cfg the global configuration
 * @param DOMDocument $doc the metadata dom document
 * @param DOMXPath $xpath an xpath evaluator instance on the dom document
 * @param DOMElement $desc an EntityDescriptor element
 * @param DOMElement $sp_desc an SPSSODescriptor element
 * @param string $entityid the entity identifier of the IDP
 */
function pf_connection_create_sp(&$cfg, $doc, $xpath, $desc, $sp_desc, $entityid) {

	$role_ext = pf_connection_create_extensions_role($cfg, $doc, $xpath, $sp_desc, $entityid);
	
	$sp = $doc->createElement('urn:SP');
		
	$mapping = $doc->createElement('urn:AdapterToAssertionMapping');
	$mapping->setAttribute('AdapterInstanceId', $cfg['adapter']['idp']['instance']);
	$default_map = $doc->createElement('urn:DefaultAttributeMapping');	
		
	$acs = $xpath->query('md:SPSSODescriptor/md:AttributeConsumingService', $desc);
	if ($acs->length != 0) {
		foreach ($xpath->query('md:RequestedAttribute', $acs->item(0)) as $attr) {
			$map = $doc->createElement('urn:AttributeMap');
			$map->setAttribute('Value', array_key_exists($attr->getAttribute('Name'), $cfg['adapter']['idp']['attribute-map']) ? $cfg['adapter']['idp']['attribute-map'][$attr->getAttribute('Name')] : 'subject');
			$map->setAttribute('Type', 'Adapter');
			$map->setAttribute('Name', $attr->getAttribute('Name'));
			$default_map->appendChild($map);
		}		
	}

	$map = $doc->createElement('urn:AttributeMap');
	$map->setAttribute('Value', array_key_exists('SAML_SUBJECT', $cfg['adapter']['idp']['attribute-map']) ? $cfg['adapter']['idp']['attribute-map']['SAML_SUBJECT'] : 'subject');
	$map->setAttribute('Type', 'Adapter');
	$map->setAttribute('Name', 'SAML_SUBJECT');
	$default_map->appendChild($map);

	$mapping->appendChild($default_map);
	
	// needed for SAML 1.1 purposes
	$sp->setAttribute("DefaultTargetResource", $cfg['dummy-default-targetresource']);
	
/*
	TODO: may want an additional attribute contract specification as last element in the SPSSO descriptor, if not already there

 	<md:AttributeConsumingService index="0">
      <md:ServiceName xml:lang="en">AttributeContract</md:ServiceName>
      <md:RequestedAttribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="sn"/>
    </md:AttributeConsumingService>
*/	
	
	$sp->appendChild($mapping);
	$role_ext->appendChild($sp);
	
	pf_connection_save($cfg, $doc, $desc, $entityid);
}

/**
 * Evaluate if a connection should be skipped for creation/deletion because it has been configured so in the include/exclude settings.
 * 
 * @param array $cfg the global configuration
 * @param string $entityid the entityid that we want to evaluate
 */
function pf_connection_skip(&$cfg, $entityid) {
	if (array_key_exists('exclude', $cfg)) {
		if (in_array($entityid, $cfg['exclude'])) return true;
	}
	if ( (array_key_exists('include', $cfg)) and (count($cfg['include']) > 0) ) {
		if (!in_array($entityid, $cfg['include'])) return true;
	}
	return FALSE;	
}

/**
 * Modifies a connection name if it clashes with an already existing one; in that case adds a sequence number to it.
 * 
 * @param array $cfg the global configuration
 * @param string $name the IDP/SP name that we want to lookup
 * @param string $type indicates whether this is an IDP ("idp") or SP ("sp") name
 */
function pf_connection_name_duplicate_fix(&$cfg, $name, $type) {
	if (array_key_exists($name, $cfg['duplicate-name-fix'][$type])) {
		$cfg['duplicate-name-fix'][$type][$name] += 1;
		$name .= ' (' . $cfg['duplicate-name-fix'][$type][$name] . ')';
	} else {
		$cfg['duplicate-name-fix'][$type][$name] = 1;
	}		
	return $name;
}

/**
 * Deletes an optional "mailto:" prefix from the EmailAddress in an EntityDescriptor's ContactPerson element
 * because PingFederate chokes on it.
 * 
 * @param array $cfg the global configuration
 * @param DOMDocument $doc the metadata dom document
 * @param DOMXPath $xpath an xpath evaluator instance on the dom document
 * @param DOMElement $desc an EntityDescriptor element
 * 
 */
function pf_connection_contact_mailto_fix(&$cfg, $doc, $xpath, $desc) {
	foreach ($xpath->query('md:ContactPerson', $desc) as $contact) {
		foreach ($xpath->query('md:EmailAddress', $contact) as $address) {
			if (strpos($address->textValue, 'mailto:') == 0) {
				$address->firstChild->replaceData(0, strlen('mailto:'), '');
			}
		}
	}
}


/**
 * Modify the protocolSupportEnumeration so that if it contains the preferred protocol, it will remove the other supported protocol.
 * This is used to fix PingFederate's preference for the first listed protocol.
 * 
 * @param array $cfg the global configuration
 * @param DOMElement $sso_desc and SPSSODescriptor or IDPSSODescriptor element
 */
function pf_connection_prefer_saml20(&$cfg, $sso_desc) {
	$proto_enum = $sso_desc->getAttribute('protocolSupportEnumeration');
	$protos = explode(" ", $proto_enum);
	if ( (count($protos) > 0) and in_array($cfg['preferred-protocol'], $protos)) $sso_desc->setAttribute('protocolSupportEnumeration', $cfg['preferred-protocol']);
	return $sso_desc;
}

/**
 * Create a connection (SP/IDP, SAML2.0/SAML1.1) in PingFederate.
 * 
 * @param array $cfg the global configuration
 * @param DOMDocument $doc the metadata dom document
 * @param DOMElement $desc an EntityDescriptor element
 * @param DOMXPath $xpath an xpath evaluator instance on the dom document
 */
function pf_connection_create(&$cfg, $doc, $desc, $xpath) {
	
	$entityid = $desc->getAttribute('entityID');

	if (pf_connection_skip($cfg, $entityid)) return NULL;
	
	$name = '[P] '; // to indicate that this connection was provisioned
	$org = $xpath->query('md:Organization/md:OrganizationName', $desc);
	$name .= ($org->length > 0) ? $org->item(0)->textContent : $entityid;

	//pf_connection_contact_mailto_fix($cfg, $doc, $xpath, $desc);
	
	$desc->setAttributeNS('urn:sourceid.org:saml2:metadata-extension:v2', 'urn:isActive', 'true');

	$extensions = $xpath->query('md:Extensions', $desc);
	if ($extensions->length > 0) {
		echo " # WARN: ignoring unsupported extensions for entity \"$entityid\":\n";
		echo $doc->saveXML($extensions->item(0)) . "\n\n";
		$desc->removeChild($extensions->item(0));
	}
	
	$extensions = $doc->createElementNS('urn:oasis:names:tc:SAML:2.0:metadata', 'md:Extensions');
	$desc->insertBefore($extensions, $desc->firstChild);
	$entity_ext = $doc->createElement('urn:EntityExtension');

/*
	$encryption = $doc->createElement('urn:Encryption');
	$encryption_policy = $doc->createElement('urn:EncryptionPolicy');
	$encryption_policy->setAttribute('EncryptAssertion', 'true');
	$encryption_policy->setAttribute('KeyTransportAlgorithm', 'http://www.w3.org/2001/04/xmlenc#rsa-1_5');
	$encryption_policy->setAttribute('EncryptionAlgorithm', 'http://www.w3.org/2001/04/xmlenc#aes128-cbc');
	$encryption->appendChild($encryption_policy);
	$entity_ext->appendChild($encryption);
*/

	$dependencies = $doc->createElement('urn:Dependencies');
	$signing_key = $doc->createElement('urn:SigningKeyPairReference');
	$signing_key->setAttribute('MD5Fingerprint', $cfg['signing-key-fingerprint']);
	$dependencies->appendChild($signing_key);

/*
	$encryption_cert = $doc->createElement('urn:EncryptionCert');
	$base64_cert = $doc->createElement('urn:Base64EncodedCert', 'MIIDGzCCAgOgAwIBAgIJANI+yGM0M1N2MA0GCSqGSIb3DQEBBQUAMCcxJTAjBgNVBAMTHGx0Y2F3aWtpMDEuaXQub2hpby1zdGF0ZS5lZHUwHhcNMTAwNzA3MjI0MzA1WhcNMjAwNzA0MjI0MzA1WjAnMSUwIwYDVQQDExxsdGNhd2lraTAxLml0Lm9oaW8tc3RhdGUuZWR1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5fsEv25Mr9wfa48qfjn8m40yB/lwimJ8dSnYw2erd/tfB+sPESw42Is5Lv2B3pI3mj9a0PT0Gf1VgUoQW0RCT6L4VOW50WsPFv/RKPfT/AIRl00dTCqb440PgotGbrK9ivZqlvkzlSGUKuFcg2gLj+CJlbMcwEneSwn0FE1xKEGpMDUk91lZH1XxmnIDDOQn1G5qul4qAbXITMpLi2MlsHAEXxnLrthFFas6zDrviTwHcqGXq9zJJkPHDcbu1qg6AUT7bRJrqszxxktSV6mFclkgLPpcVkigMR8RNVMQkWaaWSnfBkFy2iAe3xw3DNp7obtzgItYi9N8U6K5qorSkQIDAQABo0owSDAnBgNVHREEIDAeghxsdGNhd2lraTAxLml0Lm9oaW8tc3RhdGUuZWR1MB0GA1UdDgQWBBR32XnCliG78DdyTtZhyIQSHChtyjANBgkqhkiG9w0BAQUFAAOCAQEAVEweCxPElHGmam4Iv2QeJsGE7m4de7axp3epAJb7uVbNZ2P1S/s4GZQhmGsUoGoxwqca3wyQ+C1ZkpQJdyFl5s1tFc26D+Z0KTDo174GzO9iI9SeQ4YSp3FNhZqxn4xH3DULzzHwoVSwFr5irLPAVtrqK8H/rzBREhqOse2VSJ/1PkI+p7lUiElIzMiObLGjumF2fDOPkXOSMNyC4c5oCCJtcrip/BaLo6bqdqn3DKP8onMw/lHZQolyVsupuhGsSX13WVJ0uyGvuA7hiHnGEkpDmskUd3TsriyQAt47RZzYtTupO/NdWvz8SvXU1qIOk9CTQ0D2b2OOftfUW+FuAQ==');
	$encryption_cert->appendChild($base64_cert);
	$dependencies->appendChild($encryption_cert);
*/
	
	// needed for Artifact SOAP backchannel profile (incoming, ao. for SAML 1.1), and for Attribute Query (outgoing)
	$soap_auth = $doc->createElement('urn:SoapAuth');
	$soap_auth->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:soap', 'http://www.sourceid.org/2004/04/soapauth');
	
	$incoming = $doc->createElement('soap:Incoming');
	$none_incoming = $doc->createElement('soap:None');
	$none_incoming->setAttribute('providerID','this');	
	$incoming->appendChild($none_incoming);
	// if SAML 1.1
	$basic_incoming = $doc->createElement('soap:Basic');
	$basic_incoming->setAttribute('providerID','this');	
	$basic_incoming->setAttribute('password', $cfg['basic-auth-password']);
	$incoming->appendChild($basic_incoming);
	$soap_auth->appendChild($incoming);

	$outgoing = $doc->createElement('soap:Outgoing');
	$none_outgoing = $doc->createElement('soap:None');
	$none_outgoing->setAttribute('providerID','this');
	$outgoing->appendChild($none_outgoing);
	// if SAML 1.1
	$basic_outgoing = $doc->createElement('soap:Basic');
	$basic_outgoing->setAttribute('providerID','this');
	$basic_outgoing->setAttribute('password', $cfg['basic-auth-password']);	
	$outgoing->appendChild($basic_outgoing);
	$soap_auth->appendChild($outgoing);
	$dependencies->appendChild($soap_auth);

	$entity_ext->appendChild($dependencies);
	$extensions->appendChild($entity_ext);
	
	$idp_desc = $xpath->query('md:IDPSSODescriptor', $desc);
	if ($idp_desc->length > 0) {
		$username = urlencode('idp:' . $entityid);
		$basic_incoming->setAttribute('username', $username);
		$basic_outgoing->setAttribute('username', $username);
		$desc->setAttribute('urn:name', pf_connection_name_duplicate_fix($cfg, $name, 'idp'));
		$idp_desc = $idp_desc->item(0);
		$idp_desc = pf_connection_prefer_saml20($cfg, $idp_desc);
		pf_connection_create_idp($cfg, $doc, $xpath, $desc, $idp_desc, $entityid);
		// NB: this relies on the fact that PF will process only the IDPSSODescriptor if it has both IDPSSODescriptor and SPSSODescriptor!
		$desc->removeChild($idp_desc);
	}
	
	$sp_desc = $xpath->query('md:SPSSODescriptor', $desc);
	if ($sp_desc->length > 0) {
		$username = urlencode('sp:' . $entityid);
		$basic_incoming->setAttribute('username', $username);
		$basic_outgoing->setAttribute('username', $username);
		$desc->setAttribute('urn:name', pf_connection_name_duplicate_fix($cfg, $name, 'sp'));
		$sp_desc = $sp_desc->item(0);
		$sp_desc = pf_connection_prefer_saml20($cfg, $sp_desc);
		pf_connection_create_sp($cfg, $doc, $xpath, $desc, $sp_desc, $entityid);
	}
	
	return true;
}

/**
 * Delete a connection (SP/IDP, SAML2.0/SAML1.1) in PingFederate.
 * 
 * @param array $cfg the global configuration
 * @param DOMDocument $doc the metadata dom document
 * @param DOMElement $desc an EntityDescriptor element
 * @param DOMXPath $xpath an xpath evaluator instance on the dom document
 */
function pf_connection_delete(&$cfg, $doc, $desc, $xpath) {
	
	$entityid = $desc->getAttribute('entityID');
	
	if (pf_connection_skip($cfg, $entityid)) return NULL;
	
	$roles = array();
	$sso_desc = $xpath->query('md:IDPSSODescriptor', $desc);
	if ($sso_desc->length > 0) $roles[] = 'IDP';
	$sso_desc = $xpath->query('md:SPSSODescriptor', $desc);
	if ($sso_desc->length > 0) $roles[] = 'SP';
	
	foreach ($roles as $role) {
		$body = '<deleteConnection><param0>' . htmlspecialchars($entityid) . '</param0><param1>' . $role . '</param1></deleteConnection>';
		$result = soap_call_basic_auth($cfg['connection-management-url'], '', $body, $cfg['user'], $cfg['password']);
		if ($result !== PF_DELETE_CONN_RSP_OK) {
			echo "\n$result\n";
			echo "\n # ERROR: deleting the connection for \"$entityid\" failed.\n";
			exit;
		}
	}
	return true;
}

/**
 * Process a metadata document that contains an EntitiesDescriptor (with embedded EntityDescriptors) or one or more EntityDescriptors (not embedded).
 * 
 * @param array $cfg the global configuration
 * @param DOMDocument $doc the metadata dom document
 * @param string $function the callback function to call upon processing metadata (eg. create or delete the associated entity(s))
 */
function process_metadata(&$cfg, $doc, $function) {
	$xpath = new DOMXpath($doc);
	$xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
	$descriptor = $xpath->query('/md:EntitiesDescriptor', $doc->documentElement);
	if ($descriptor->length > 0) {
			// process multiple EntityDescriptor's contained in an EntitiesDescriptor
			foreach ($xpath->query('md:EntityDescriptor', $descriptor->item(0)) as $desc) {
				$result = $function($cfg, $doc, $desc, $xpath);
			}
	} else {
			// process one or more EntityDescriptor's in a flat file
			foreach ($xpath->query('/md:EntityDescriptor', $doc->documentElement) as $desc) {
				$result = $function($cfg, $doc, $desc, $xpath);
			}
	}
	return true;
}

/** 
 * Printout program usage.
 * 
 * @param array $argv arguments passed on the commandline
 */
function usage($argv) {
	echo "Usage: $argv[0] [create|delete]\n";
}

if (count($argv) > 1) {
	switch ($argv[1]) {
		case 'create':
		case 'delete':
			$md = count($argv) > 2 ? $argv[2] : $config['metadata-url'];
			$cert = count($argv) > 3 ? $argv[3] : (array_key_exists('metadata-certificate', $config) ? $config['metadata-certificate'] : NULL);
			$doc = metadata_retrieve_and_verify($md, ($cert !== NULL) ? file_get_contents($cert) : NULL);
			process_metadata($config, $doc, 'pf_connection_' . $argv[1]);
			break;
		case 'get':
			$result = pf_connection_get($config, $argv[2], count($argv) > 3 ? $argv[3] : "SP");
			print html_entity_decode($result);
		 	break;
		case 'save':
			$metadata = file_get_contents($argv[2]);
			$doc = new DOMDocument(true);
			$doc->loadXML($metadata);
			$xpath = new DOMXpath($doc);
			$xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
			$desc = $xpath->query('/md:EntityDescriptor', $doc->documentElement);
			$entityid = $desc->item(0)->getAttribute('entityID');
			$result = pf_connection_save($config, $doc, $desc->item(0), $entityid);
			break;
		default:
			usage($argv);
			break;
	}
} else {
	usage($argv);
}

?>

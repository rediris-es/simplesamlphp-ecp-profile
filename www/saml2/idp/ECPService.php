<?php
/*
 *  IdPRef - IdP de Referencia para SIR 2 basado en SimpleSAMLPHP v1.13.1
 * =========================================================================== *
 *
 * Copyright (C) 2014 - 2015 by the Spanish Research and Academic Network.
 * This code was developed by Auditoria y Consultoría de Privacidad y Seguridad
 * (PRiSE http://www.prise.es) for the RedIRIS SIR service (SIR: 
 * http://www.rediris.es/sir)
 *
 * *****************************************************************************
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 * ************************************************************************** */

/**
 * Description of SAML2_PAOS
 * 
 * @package    IdPRef\www\saml2\idp
 * @author     "PRiSE [Auditoria y Consultoria de privacidad y Seguridad, S.L.]"
 * @copyright  Copyright (C) 2014 - 2015 by the Spanish Research and Academic
 *             Network
 * @license    http://www.apache.org/licenses/LICENSE-2.0  Apache License 2.0
 * @version    0.3-Sprint3-R57
 */
require_once('../../_include.php');

$debug = 0;

$config = SimpleSAML_Configuration::getInstance();
if (!$config->getBoolean('enable.saml20-idp', FALSE)) {
    throw new SimpleSAML_Error_Error('NOACCESS');
}

$metadata    = SimpleSAML_Metadata_MetaDataStorageHandler::getMetadataHandler();
$idpEntityId = $metadata->getMetaDataCurrentEntityID('saml20-idp-hosted');
$idpMetadata = $metadata->getMetaDataConfig($idpEntityId, 'saml20-idp-hosted');

/*
  $store = SimpleSAML_Store::getInstance();
  if ($store === FALSE) {
  }

  $binding = new SAML2_SOAP();
  $request = $binding->receive();

  $issuer     = $request->getIssuer();
  $spMetadata = $metadata->getMetadataConfig($issuer, 'saml20-sp-remote');

 * 
 */
$username = !empty($_SERVER['PHP_AUTH_USER']) ? $_SERVER['PHP_AUTH_USER'] : null;
$password = !empty($_SERVER['PHP_AUTH_PW']) ? $_SERVER['PHP_AUTH_PW'] : null;
if ($username === NULL || $password === NULL) {
    header('WWW-Authenticate: Basic realm="My Realm"');
    header('HTTP/1.0 401 Unauthorized');
    echo 'Text to send if user hits Cancel button';
    exit;
}

$metadata    = SimpleSAML_Metadata_MetaDataStorageHandler::getMetadataHandler();
$idpEntityId = $metadata->getMetaDataCurrentEntityID('saml20-idp-hosted');
$idp         = SimpleSAML_IdP::getById('saml2:' . $idpEntityId);

$auth       = $idp->getConfig()->getString('auth');
$authSource = null;
if (SimpleSAML_Auth_Source::getById($auth) !== NULL) {
    $authSource = new SimpleSAML_Auth_Simple($auth);
}
if ($debug) {
    var_dump($authSource);
}
/* Attempt to log in. */
/*
  try {
  $attributes = $authSource->getAuthSource()->login($username, $password);
  } catch (Exception $e) {
  SimpleSAML_Logger::stats('Unsuccessful login attempt from '.$_SERVER['REMOTE_ADDR'].'.');
  throw $e;
  }
 * 
 */
try {
    $binding = SAML2_Binding::getCurrentBinding();
    $request = $binding->receive();

    if (!($request instanceof SAML2_AuthnRequest)) {
        throw new SimpleSAML_Error_BadRequest('Message received on authentication request endpoint wasn\'t an authentication request.');
    }

    $spEntityId = $request->getIssuer();
    if ($spEntityId === NULL) {
        throw new SimpleSAML_Error_BadRequest('Received message on authentication request endpoint without issuer.');
    }
    $spMetadata = $metadata->getMetaDataConfig($spEntityId, 'saml20-sp-remote');

    sspmod_saml_Message::validateMessage($spMetadata, $idpMetadata, $request);

    $supportedBindings = array(SAML2_Const::BINDING_PAOS);
    $consumerURL       = $request->getAssertionConsumerServiceURL();
    $protocolBinding   = $request->getProtocolBinding();
    $consumerIndex     = $request->getAssertionConsumerServiceIndex();
    $acsEndpoint       = sspmod_saml_IdP_SAML2::getAssertionConsumerService($supportedBindings, $spMetadata, $consumerURL, $protocolBinding, $consumerIndex);
    $relayState        = $request->getRelayState();

    $requestId = $request->getId();

    $state                                        = array();
    $state[sspmod_core_Auth_UserPassBase::AUTHID] = $auth;
    $state['LoginCompletedHandler']               = "ecp_finish_auth";
    $state['SPMetadata']                          = $spMetadata->toArray();
    $state['saml:RequestId']                      = $requestId;
    $state['saml:RelayState']                     = $relayState;
    $state['saml:ConsumerURL']                    = $acsEndpoint['Location'];
    $state['saml:Binding']                        = $acsEndpoint['Binding'];
    $state['core:IdP']                            = $idp->getId();

    /* Save the $state-array, so that we can restore it after a redirect. */
    $authStateId = SimpleSAML_Auth_State::saveState($state, sspmod_core_Auth_UserPassBase::STAGEID);
    sspmod_core_Auth_UserPassBase::handleLogin($authStateId, $username, $password);
} catch (SimpleSAML_Error_Error $e) {
    /* Login failed. Extract error code and parameters, to display the error. */
    $errorCode   = $e->getErrorCode();
    $errorParams = $e->getParameters();
    if ($debug) {
        var_dump($errorCode);
        var_dump($errorParams);
    }
}

function ecp_finish_auth($state) {
    $state['AuthnInstant'] = time();
//    var_dump("******************");
//    var_dump($state);
//    var_dump("******************");
    sspmod_saml_IdP_SAML2::sendResponse($state);
}

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
 * @package    IdPRef\vendor\samls\src\SAML2
 * @author     "PRiSE [Auditoria y Consultoria de privacidad y Seguridad, S.L.]"
 * @copyright  Copyright (C) 2014 - 2015 by the Spanish Research and Academic
 *             Network
 * @license    http://www.apache.org/licenses/LICENSE-2.0  Apache License 2.0
 * @version    0.3-Sprint3-R57
 */
class SAML2_PAOS extends SAML2_SOAP {

    public function send(\SAML2_Message $message) {
        header('Content-Type: text/xml', TRUE);
        $outputFromIdp = '<?xml version="1.0" encoding="UTF-8"?>';
        $outputFromIdp .= '<SOAP-ENV:Envelope xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">';
        $outputFromIdp .= '<SOAP-ENV:Header>';
        $outputFromIdp .= '<ecp:Response SOAP-ENV:mustUnderstand="1" SOAP-ENV:actor="http://schemas.xmlsoap.org/soap/actor/next" AssertionConsumerServiceURL="'.$message->getDestination().'"/>';
        $outputFromIdp .= '</SOAP-ENV:Header>';
        $outputFromIdp .= '<SOAP-ENV:Body>';
        $xmlMessage = $message->toSignedXML();
        SAML2_Utils::getContainer()->debugMessage($xmlMessage, 'out');
        $tempOutputFromIdp = $xmlMessage->ownerDocument->saveXML($xmlMessage);
        $outputFromIdp .= $tempOutputFromIdp;
        $outputFromIdp .= '</SOAP-ENV:Body>';
        $outputFromIdp .= '</SOAP-ENV:Envelope>';
        print($outputFromIdp);
        exit(0);
    }

//put your code here
}

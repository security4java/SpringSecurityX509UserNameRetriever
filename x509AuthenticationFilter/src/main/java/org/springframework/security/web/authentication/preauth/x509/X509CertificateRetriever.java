/*
 * 	Copyright 2012 Michael Furman
 * 
 * 	Licensed under the Apache License, Version 2.0 (the "License");
 * 	you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  
 *         http://www.apache.org/licenses/LICENSE-2.0
 *         
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *  
 */

package org.springframework.security.web.authentication.preauth.x509;

import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;

/**
 * The interface <b>X509CertificateRetriever</b> defines how to retrieve a X509Certificate from HttpServletRequest.
 */
public interface X509CertificateRetriever {
	X509Certificate getClientCertificate(HttpServletRequest request);
}

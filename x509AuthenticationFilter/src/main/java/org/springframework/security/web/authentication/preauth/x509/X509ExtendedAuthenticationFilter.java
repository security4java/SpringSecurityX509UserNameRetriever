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

import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.x509.X509SubjectAlternativeNameConstants.X509UserNameRetrieveField;

/**
 * 
 * @author Michael Furman
 */
public class X509ExtendedAuthenticationFilter extends AbstractPreAuthenticatedProcessingFilter {
    private X509CertificateRetriever clientCertificateRetriever = new X509CertificateRetrieverAttribute();
	private String x509UserNameRetrieverConfiguration = null;
	private String x509UserNameRetrieveField;
	private X509UserNameRetriever userNameRetriever = null;
    
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        X509Certificate clientCert = extractClientCertificate(request);

        if (clientCert == null) {
            return null;
        }
      
        String extractPrincipal = userNameRetriever.getUserName(clientCert);
        return extractPrincipal;
    }

    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return extractClientCertificate(request);
    }

    private X509Certificate extractClientCertificate(HttpServletRequest request) {
    	
    	X509Certificate x509Certificate = clientCertificateRetriever.getClientCertificate(request);
    	if (x509Certificate != null) {
            return x509Certificate;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("No client certificate found in request.");
        }

        return null;
    }

    public void setX509UserNameRetrieverConfiguration(String x509UserNameRetrieverConfiguration) { 
    	this.x509UserNameRetrieverConfiguration = x509UserNameRetrieverConfiguration;		
	}
    
    
	public void setX509UserNameRetrieveField(String x509UserNameRetrieveField) {
		this.x509UserNameRetrieveField = x509UserNameRetrieveField;	
	}

	@Override
	public void afterPropertiesSet() {
		super.afterPropertiesSet();
		if (X509UserNameRetrieveField.SubjectDN.equals(x509UserNameRetrieveField)) {
			if (x509UserNameRetrieverConfiguration == null) {
			     userNameRetriever = new X509SubjectDnRetriever();		    			
			} else {
				userNameRetriever = new X509SubjectDnRetriever(x509UserNameRetrieverConfiguration);
			}			
		} else if (X509UserNameRetrieveField.SubjectAlternativeName.equals(x509UserNameRetrieveField)) {						
			if (x509UserNameRetrieverConfiguration == null) {
				userNameRetriever = new X509SubjectDnRetriever();				
				String warnString = "Can not create userNameRetriever : userNameRetrieveFieldPart is null when userNameRetrieveField is [" + x509UserNameRetrieveField + "]. userNameRetriever is created for SubjectDn field.";
				logger.warn(warnString);				
			} else {
				userNameRetriever = new X509SubjectAlternativeNameRetriever(x509UserNameRetrieverConfiguration);
			}
		} else {
			userNameRetriever = new X509SubjectDnRetriever();
		}
	}

}

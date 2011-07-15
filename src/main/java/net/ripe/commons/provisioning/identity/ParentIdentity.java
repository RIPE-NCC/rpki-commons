/**
 * The BSD License
 *
 * Copyright (c) 2010, 2011 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.commons.provisioning.identity;

import java.net.URI;

import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificate;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamAsAttribute;

@XStreamAlias(ParentIdentity.PARENT_IDENTITY_NODE_NAME)
public class ParentIdentity {

    public static final String XMLNS = "http://www.hactrn.net/uris/rpki/myrpki/";
    public static final String PARENT_IDENTITY_NODE_NAME = "parent";
    
    public static final int VERSION = 2;
    
    public ParentIdentity(URI upDownUrl, String parentHandle,
			String childHandle,
			ProvisioningIdentityCertificate parentIdCertificate,
			ProvisioningIdentityCertificate childIdCertificate,
			RepositoryDefinition repositoryDefinition) {
		this.upDownUrl = upDownUrl;
		this.parentHandle = parentHandle;
		this.childHandle = childHandle;
		this.parentIdCertificate = parentIdCertificate;
		this.childIdCertificate = childIdCertificate;
		this.repositoryDefinition = repositoryDefinition;
	}


    @SuppressWarnings("unused")
    @XStreamAsAttribute
    @XStreamAlias("version")
    private final int version = VERSION;
    
	@XStreamAsAttribute
    @XStreamAlias("child_handle")
    private String childHandle;
    
    @XStreamAsAttribute
    @XStreamAlias("parent_handle")
    private String parentHandle;
    
    @XStreamAsAttribute
    @XStreamAlias("service_uri")
    private URI upDownUrl;
    
    @XStreamAlias("bpki_resource_ta")
    private ProvisioningIdentityCertificate parentIdCertificate;
    
    @XStreamAlias("bpki_child_ta")
    private ProvisioningIdentityCertificate childIdCertificate;
    
    @XStreamAlias("repository")
    private RepositoryDefinition repositoryDefinition;

    
    public String getChildHandle() {
        return childHandle;
    }
    
    public String getParentHandle() {
        return parentHandle;
    }

    
    public ProvisioningIdentityCertificate getParentIdCertificate() {
        return parentIdCertificate;
    }
    
    public ProvisioningIdentityCertificate getChildIdCertificate() {
        return childIdCertificate;
    }
    
    public RepositoryDefinition getRepositoryDefinition() {
        return repositoryDefinition;
    }

    public URI getUpDownUrl() {
        return upDownUrl;
    }

}

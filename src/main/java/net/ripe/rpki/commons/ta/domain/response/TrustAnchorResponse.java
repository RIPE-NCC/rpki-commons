/**
 * The BSD License
 *
 * Copyright (c) 2010-2020 RIPE NCC
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
package net.ripe.rpki.commons.ta.domain.response;


import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.util.EqualsSupport;
import org.apache.commons.lang3.Validate;

import java.io.Serializable;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class TrustAnchorResponse extends EqualsSupport implements Serializable {

    private static final long serialVersionUID = 1L;

    private final Long requestCreationTimestamp;
    private List<TaResponse> taResponses;
    private final Map<URI, CertificateRepositoryObject> publishedObjects;

    public TrustAnchorResponse(final Long requestCreationTimestamp,
                               final Map<URI, CertificateRepositoryObject> publishedObjects,
                               final List<TaResponse> taResponses) {
        Validate.notNull(requestCreationTimestamp, "requestCreationTimestamp is required");
        Validate.notEmpty(publishedObjects, "publishedObjects is required");

        this.requestCreationTimestamp = requestCreationTimestamp;
        this.publishedObjects = new TreeMap<>(publishedObjects);
        this.taResponses = (taResponses == null) ? new ArrayList<TaResponse>() : taResponses;
    }

    public Long getRequestCreationTimestamp() {
        return requestCreationTimestamp;
    }

    public Map<URI, CertificateRepositoryObject> getPublishedObjects() {
        return Collections.unmodifiableMap(publishedObjects);
    }

    public List<TaResponse> getTaResponses() {
        return taResponses;
    }

    public static Builder newBuilder(Long requestCreationTimestamp) {
        return new Builder(requestCreationTimestamp);
    }

    public boolean containsSigningOrRevocationResponse() {
        for (TaResponse taResponse : taResponses) {
            if (taResponse instanceof SigningResponse || taResponse instanceof RevocationResponse) {
                return true;
            }
        }
        return false;
    }

    public final static class Builder {

        private Long requestCreationTimestamp;
        private Map<URI, CertificateRepositoryObject> publishedObjects = new TreeMap<URI, CertificateRepositoryObject>();
        private List<TaResponse> taResponses = new ArrayList<TaResponse>();

        private Builder(Long requestCreationTimestamp) {
            this.requestCreationTimestamp = requestCreationTimestamp;
        }

        public TrustAnchorResponse build() {
            return new TrustAnchorResponse(requestCreationTimestamp, publishedObjects, taResponses);
        }

        public Builder addTaResponse(TaResponse taResponse) {
            Validate.notNull(taResponse, "taResponse is required");
            taResponses.add(taResponse);
            return this;
        }

        public Builder addPublishedObjects(Map<URI, CertificateRepositoryObject> publishedObjects) {
            for (URI file : publishedObjects.keySet()) {
                addPublishedObject(file, publishedObjects.get(file));
            }
            return this;
        }

        public Builder addPublishedObject(URI file, CertificateRepositoryObject publishedObject) {
            Validate.notNull(file, "file is required");
            Validate.notNull(publishedObject, "publishedObject is required");
            Validate.isTrue(!publishedObjects.containsKey(file), "duplicate file name");
            publishedObjects.put(file, publishedObject);
            return this;
        }
    }
}

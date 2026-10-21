/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.airlift.vault.enums;

/**
 * How Trino authenticates to the OpenBao or HashiCorp Vault server.
 */
public enum VaultAuthMethod
{
    /**
     * The token of {@code vault.token} or {@code vault.token-file}, used as it is.
     */
    TOKEN,
    /**
     * {@code POST /v1/auth/<mount>/login} with a role id and a secret id.
     */
    APPROLE,
    /**
     * {@code POST /v1/auth/<mount>/login} with the projected service account token of the pod.
     */
    KUBERNETES,
    /**
     * A keytab-based Kerberos client login over verified HTTPS.
     */
    KERBEROS,
}

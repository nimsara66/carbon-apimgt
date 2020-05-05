/*
 *  Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.apimgt.rest.api.endpoint.registry.util;

import org.wso2.carbon.apimgt.api.model.EndpointRegistry;
import org.wso2.carbon.apimgt.rest.api.endpoint.registry.dto.RegistryDTO;

/**
 * This class is responsible for mapping APIM core Endpoint Registry related objects into REST API
 * Endpoint Registry related DTOs
 */
public class EndpointRegistryMappingUtils {

    /**
     * Converts a RegistryDTO object into EndpointRegistry object
     *
     * @param registryDTO RegistryDTO object
     * @return EndpointRegistry corresponds to RegistryDTO object
     */
    public static EndpointRegistry fromDTOtoEndpointRegistry(RegistryDTO registryDTO, String owner) {
        EndpointRegistry registry = new EndpointRegistry();
        registry.setName(registryDTO.getName());
        registry.setOwner(owner);
        registry.setType(registryDTO.getType().toString());
        registry.setMode(registryDTO.getMode().toString());
        return registry;
    }

    /**
     * Converts a EndpointRegistry object into RegistryDTO object
     *
     * @param registry EndpointRegistry object
     * @return RegistryDTO corresponds to EndpointRegistry object
     */
    public static RegistryDTO fromEndpointRegistrytoDTO(EndpointRegistry registry) {
        RegistryDTO registryDTO = new RegistryDTO();
        registryDTO.setName(registry.getName());
        registryDTO.setType(RegistryDTO.TypeEnum.valueOf(registry.getType()));
        registryDTO.setMode(RegistryDTO.ModeEnum.valueOf(registry.getMode()));
        return registryDTO;
    }

}

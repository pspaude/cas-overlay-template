package org.apereo.cas.authentication.principal;

import org.apereo.cas.CasProtocolConstants;
import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.principal.Response.ResponseType;
import org.apereo.cas.services.ServicesManager;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.val;
import org.jasig.cas.client.util.URIBuilder;
import org.springframework.util.StringUtils;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Default response builder that passes back the ticket
 * id to the original url of the service based on the response type.
 *
 * @author Misagh Moayyed
 * @since 4.2
 */
@EqualsAndHashCode(callSuper = true)
@Getter
@Setter
public class WebApplicationServiceResponseBuilder extends AbstractWebApplicationServiceResponseBuilder {

    private static final long serialVersionUID = -851233878780818494L;

    private int order = Integer.MAX_VALUE;

    public WebApplicationServiceResponseBuilder(final ServicesManager servicesManager) {
        super(servicesManager);
    }

    @Override
    public Response build(final WebApplicationService service, final String serviceTicketId, final Authentication authentication) {
        val parameters = new HashMap<String, String>();
        if (StringUtils.hasText(serviceTicketId)) {
            parameters.put(CasProtocolConstants.PARAMETER_TICKET, serviceTicketId);
        }

        val finalService = buildInternal(service, parameters);
        val responseType = getWebApplicationServiceResponseType(finalService);

        //Handles special case for SAML2 where we need to redirect using a POST in case SAML2 Authn request (service param) is close to browsers limits
        if (finalService.getOriginalUrl().contains("/idp/profile/SAML2/Callback")) {
            val serviceUrl = new URIBuilder(finalService.getOriginalUrl());
            serviceUrl.getQueryParams().forEach(it -> parameters.put(it.getName(), it.getValue()));
            serviceUrl.clearParameters();
            return buildSAMl2Post(serviceUrl.toString(), parameters);
        }

        if (responseType == ResponseType.POST) {
            return buildPost(finalService, parameters);
        }
        if (responseType == ResponseType.REDIRECT) {
            return buildRedirect(finalService, parameters);
        }
        if (responseType == ResponseType.HEADER) {
            return buildHeader(finalService, parameters);
        }

        throw new IllegalArgumentException("Response type is valid. Only " + Arrays.toString(ResponseType.values()) + " are supported");
    }

    /**
     * Build internal service.
     *
     * @param service    the service
     * @param parameters the parameters
     * @return the service
     */
    protected WebApplicationService buildInternal(final WebApplicationService service, final Map<String, String> parameters) {
        return service;
    }

    /**
     * Builds SAML2 Callback post.
     *
     * @param service    the service
     * @param parameters the parameters
     * @return the response
     */
    protected Response buildSAMl2Post(final String serviceUrl, final Map<String, String> parameters) {
        return DefaultResponse.getPostResponse(serviceUrl, parameters);
    }
}

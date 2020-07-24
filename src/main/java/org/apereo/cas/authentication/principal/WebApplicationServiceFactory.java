package org.apereo.cas.authentication.principal;

import org.apereo.cas.CasProtocolConstants;
import org.apereo.cas.util.HttpRequestUtils;
import org.apereo.cas.validation.ValidationResponseType;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;


/**
 *  * Modified to accept a cookie representation of the CAS service parameter value!
 *
 * The {@link WebApplicationServiceFactory} is responsible for
 * creating {@link WebApplicationService} objects.
 *
 * @author Misagh Moayyed
 * @since 4.2
 */
@Slf4j
public class WebApplicationServiceFactory extends AbstractServiceFactory<WebApplicationService> {

    /**
     * Determine web application format boolean.
     *
     * @param request               the request
     * @param webApplicationService the web application service
     * @return the service itself.
     */
    private static AbstractWebApplicationService determineWebApplicationFormat(final HttpServletRequest request,
                                                                               final AbstractWebApplicationService webApplicationService) {
        val format = Optional.ofNullable(request).map(httpServletRequest -> httpServletRequest.getParameter(CasProtocolConstants.PARAMETER_FORMAT)).orElse(null);
        try {
            if (StringUtils.isNotBlank(format)) {
                val formatType = ValidationResponseType.valueOf(format.toUpperCase());
                webApplicationService.setFormat(formatType);
            }
        } catch (final Exception e) {
            LOGGER.error("Format specified in the request [{}] is not recognized", format);
        }
        return webApplicationService;
    }

    /**
     * Build new web application service simple web application service.
     *
     * @param request      the request
     * @param serviceToUse the service to use
     * @return the simple web application service
     */
    protected static AbstractWebApplicationService newWebApplicationService(final HttpServletRequest request,
                                                                            final String serviceToUse) {
        val artifactId = Optional.ofNullable(request)
                .map(httpServletRequest -> httpServletRequest.getParameter(CasProtocolConstants.PARAMETER_TICKET))
                .orElse(null);
        val id = cleanupUrl(serviceToUse);
        val newService = new SimpleWebApplicationServiceImpl(id, serviceToUse, artifactId);
        determineWebApplicationFormat(request, newService);
        val source = getSourceParameter(request, CasProtocolConstants.PARAMETER_TARGET_SERVICE,
                CasProtocolConstants.PARAMETER_SERVICE);
        newService.setSource(source);
        return newService;
    }

    /**
     * Gets requested service.
     *
     * @param request the request
     * @return the requested service
     */
    protected String getRequestedService(final HttpServletRequest request) {
        val targetService = request.getParameter(CasProtocolConstants.PARAMETER_TARGET_SERVICE);
        val service = request.getParameter(CasProtocolConstants.PARAMETER_SERVICE);
        val serviceAttribute = request.getAttribute(CasProtocolConstants.PARAMETER_SERVICE);

        if (StringUtils.isNotBlank(targetService)) {
            return targetService;
        }
        if (StringUtils.isNotBlank(service)) {
            return service;
        }
        if (serviceAttribute != null) {
            if (serviceAttribute instanceof Service) {
                return ((Service) serviceAttribute).getId();
            }
            return serviceAttribute.toString();
        }
        return null;
    }

    @Override
    public WebApplicationService createService(final HttpServletRequest request) {
        val serviceToUse = getRequestedService(request);
        if (StringUtils.isBlank(serviceToUse)) {
            try {
                if (request.getCookies() != null) {
                    val entityId = URLEncoder.encode(request.getParameter("entityId"), StandardCharsets.UTF_8);
                    final Optional<Cookie> serviceCookie = Arrays.stream(request.getCookies()).filter(c -> c.getName().equalsIgnoreCase(entityId)).findFirst();
                    if (serviceCookie.isPresent()) {
                        return newWebApplicationService(request, serviceCookie.get().getValue());
                    }
                }
            } catch (Exception e) {
                //swallowing since this method will execute for all requests
            }

            LOGGER.trace("No service is specified in the request. Skipping service creation");
            return null;
        }
        return newWebApplicationService(request, serviceToUse);
    }

    @Override
    public WebApplicationService createService(final String id) {
        val request = HttpRequestUtils.getHttpServletRequestFromRequestAttributes();
        return newWebApplicationService(request, id);
    }
}

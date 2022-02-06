package com.group5.apigateway.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.function.Predicate;
import java.util.regex.Pattern;

@RefreshScope
@Component
@Slf4j
public class AuthenticationFilter implements GatewayFilter {

    /* The endpoints in here can be accessed without any permission
     */
    private final Map<String, ImmutableList<HttpMethod>> OPEN_ENDPOINTS = new HashMap<>(){{
        put("/login", ImmutableList.of(HttpMethod.POST));
    }};

    /**
     * Maps the urls to the list of roles that are allowed to access it
     * If a url is not present here nor in the PERMISSIONLESS_ENDPOINTS then
     * It is not accessible from outside and only allowed to be called by other services
     */
    private final Map<Request, ImmutableList<String>> RESTRICTED_ENDPOINTS = new HashMap<>(){{
        put(new Request(HttpMethod.GET, Pattern.compile("\\/api\\/cas\\/users\\/[a-zA-Z0-9]*")), ImmutableList.of("DISPATCHER"));
        put(new Request(HttpMethod.POST, Pattern.compile("\\/api\\/cas\\/users\\/[a-zA-Z0-9]*")), ImmutableList.of("DISPATCHER"));
        put(new Request(HttpMethod.GET, Pattern.compile("\\/api\\/cas\\/users\\/[a-zA-Z0-9]*\\/role")), ImmutableList.of("DISPATCHER"));

        put(new Request(HttpMethod.POST, Pattern.compile("\\/api\\/ds\\/boxes")), ImmutableList.of("DISPATCHER"));
        put(new Request(HttpMethod.PUT, Pattern.compile("\\/api\\/ds\\/boxes\\/[a-zA-Z0-9]*")), ImmutableList.of("DISPATCHER"));
        put(new Request(HttpMethod.DELETE, Pattern.compile("\\/api\\/ds\\/boxes\\/[a-zA-Z0-9]*")), ImmutableList.of("DISPATCHER"));

        put(new Request(HttpMethod.PUT, Pattern.compile("\\/api\\/ds\\/collected\\/[a-zA-Z0-9]*\\/deliverer\\/[a-zA-Z0-9]*")), ImmutableList.of("DISPATCHER"));
        put(new Request(HttpMethod.PUT, Pattern.compile("\\/api\\/ds\\/deliverer\\/[a-zA-Z0-9]*\\/deposited\\/box\\/[a-zA-Z0-9]*")), ImmutableList.of("DISPATCHER"));
        put(new Request(HttpMethod.PUT, Pattern.compile("\\/api\\/ds\\/user\\/[a-zA-Z0-9]*\\/delivered\\/box\\/[a-zA-Z0-9]*")), ImmutableList.of("DISPATCHER"));

        put(new Request(HttpMethod.GET, Pattern.compile("\\/api\\/ds\\/customer\\/[a-zA-Z0-9]*\\/status\\/delivered")), ImmutableList.of("DISPATCHER", "CUSTOMER")); // Only the customer with that id
        put(new Request(HttpMethod.GET, Pattern.compile("\\/api\\/ds\\/customer\\/[a-zA-Z0-9]*\\/status\\/active")), ImmutableList.of("DISPATCHER", "CUSTOMER")); // Only the customer with that id

        put(new Request(HttpMethod.POST, Pattern.compile("\\/api\\/ds\\/deliveries")), ImmutableList.of("DISPATCHER"));
    }};

    private final RestTemplate restTemplate;

    public AuthenticationFilter(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        var path = request.getURI().getPath();
        var allowedEndpoint = OPEN_ENDPOINTS.keySet()
                .stream().anyMatch(matchesUrlAndHttpMethod(request, path));

        if (allowedEndpoint) {
            return chain.filter(exchange);
        }

        for (Request reqDefinition : RESTRICTED_ENDPOINTS.keySet()) {
            if (reqDefinition.getPattern().matcher(path).matches()) {
                if (isAuthMissing(request)) {
                    Mono<Void> response = respondWithUnauthorized(exchange, "Token is empty");
                    if (response != null) return response;
                }

                var authHeader = getAuthHeader(request);
                var token = authHeader.split(" ")[1];
                var role = getUserRole(token);

                var allowedRoles = RESTRICTED_ENDPOINTS.get(reqDefinition);

                if (!allowedRoles.contains(role)) {
                    Mono<Void> response = respondWithUnauthorized(exchange, "Unauthorized");
                    if (response != null) return response;
                }
            }
        }

        return chain.filter(exchange);
    }

    private Mono<Void> respondWithUnauthorized(ServerWebExchange exchange, String cause) {
        var response = exchange.getResponse();
        Map<String, Object> responseData = Maps.newHashMap();
        responseData.put("code", 401);
        responseData.put("message", "Illegal request");
        responseData.put("cause", cause);

        try {
            ObjectMapper objectMapper = new ObjectMapper();
            byte[] data = objectMapper.writeValueAsBytes(responseData);

            DataBuffer buffer = response.bufferFactory().wrap(data);
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            response.getHeaders().add("Content-Type", "application/json;charset=UTF-8");
            return response.writeWith(Mono.just(buffer));
        } catch (JsonProcessingException e) {
            log.error("{}", e);
        }
        return null;
    }

    private String getUserRole(final String token) {
        var url = "http://customer-authentication-service:8081/api/cas/users/role"; // TODO ISSUE IS HERE
        return restTemplate.postForObject(url, token, String.class);    // TODO FAILS
    }

    private Predicate<String> matchesUrlAndHttpMethod(ServerHttpRequest request, String path) {
        return url -> path.equals(url) && request.getMethod().equals(RESTRICTED_ENDPOINTS.get(url));
    }

    private String getAuthHeader(ServerHttpRequest request) {
        return request.getHeaders().getOrEmpty("Authorization").get(0);
    }

    private boolean isAuthMissing(ServerHttpRequest request) {
        return !request.getHeaders().containsKey("Authorization");
    }
}

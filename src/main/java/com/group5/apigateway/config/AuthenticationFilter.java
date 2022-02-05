package com.group5.apigateway.config;

import com.google.common.collect.ImmutableList;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import com.group5.apigateway.config.Request;

import java.util.*;
import java.util.regex.Pattern;

@RefreshScope
@Component
public class AuthenticationFilter implements GatewayFilter {

    /* The endpoints in here can be accessed without any permission
     */
    private final Map<String, ImmutableList<HttpMethod>> PERMISSIONLESS_ENDPOINTS = new HashMap<>(){{
        put("/login", ImmutableList.of(HttpMethod.POST));
    }};

    /**
     * Maps the urls to the list of roles that are allowed to access it
     * If a url is not present here nor in the PERMISSIONLESS_ENDPOINTS then
     * It is not accessible from outside and only allowed to be called by other services
     */
    private final Map<Request, ImmutableList<String>> PERMISSIONED_ENDPOINTS = new HashMap<>(){{
        put(new Request(HttpMethod.GET, Pattern.compile("\\/user\\/[a-zA-Z0-9]*")), ImmutableList.of("DISPATCHER"));
        //put(new Request(HttpMethod.POST, "/users/*"), ImmutableList.of("DISPATCHER"));
        //put(new Request(HttpMethod.GET, "/users/*/role"), ImmutableList.of("DISPATCHER"));

        //put(new Request(HttpMethod.POST, "/boxes"), ImmutableList.of("DISPATCHER"));
        //put(new Request(HttpMethod.PUT, "/boxes/*"), ImmutableList.of("DISPATCHER"));
        //put(new Request(HttpMethod.DELETE, "/boxes/*"), ImmutableList.of("DISPATCHER"));

        put(new Request(HttpMethod.PUT, Pattern.compile("\\/collected\\/([0-9]+)(\\-)([0-9]+)\\/deliverer\\/([0-9]+)(\\-)([0-9]+)")), ImmutableList.of("DISPATCHER"));
        //put(new Request(HttpMethod.PUT, "/*/deposited/deliverer/*/box/*"), ImmutableList.of("DISPATCHER"));
        // put(new Request(HttpMethod.PUT, "/user/*/delivered/box/*"), ImmutableList.of("DISPATCHER"));

        //put(new Request(HttpMethod.GET, "/customer/*/status/delivered"), ImmutableList.of("DISPATCHER", "CUSTOMER")); // Only the customer with that id
        //put(new Request(HttpMethod.GET, "/customer/{customerId}/status/active"), ImmutableList.of("DISPATCHER", "CUSTOMER")); // Only the customer with that id

        //put(new Request(HttpMethod.POST, "/deliveries"), ImmutableList.of("DISPATCHER"));
    }};

    private final RestTemplate restTemplate;

    public AuthenticationFilter(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        var path = request.getURI().getPath();
        var allowedEndpoint = PERMISSIONLESS_ENDPOINTS.keySet()
                .stream().anyMatch(url -> path.equals(url) && request.getMethod().equals(PERMISSIONED_ENDPOINTS.get(url)));

        if (allowedEndpoint) {
            return chain.filter(exchange);
        }

        for (Request reqDefinition : PERMISSIONED_ENDPOINTS.keySet()) {
            if (reqDefinition.pattern.matcher(path).matches()) {
                System.out.println("MATCHED");
            }
        }

        return chain.filter(exchange);
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();
    }

    private String getAuthHeader(ServerHttpRequest request) {
        return request.getHeaders().getOrEmpty("Authorization").get(0);
    }

    private boolean isAuthMissing(ServerHttpRequest request) {
        return !request.getHeaders().containsKey("Authorization");
    }
}

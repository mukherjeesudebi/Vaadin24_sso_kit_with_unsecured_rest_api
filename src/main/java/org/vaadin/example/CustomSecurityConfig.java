package org.vaadin.example;

import java.util.Objects;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.savedrequest.RequestCache;

import com.vaadin.flow.spring.security.VaadinSavedRequestAwareAuthenticationSuccessHandler;
import com.vaadin.flow.spring.security.VaadinWebSecurity;
import com.vaadin.sso.core.BackChannelLogoutFilter;
import com.vaadin.sso.starter.SingleSignOnProperties;
import com.vaadin.sso.starter.UidlExpiredSessionStrategy;
import com.vaadin.sso.starter.UidlRedirectStrategy;

@Configuration
@EnableWebSecurity
public class CustomSecurityConfig extends VaadinWebSecurity {

	private final SingleSignOnProperties properties;

	private final OidcClientInitiatedLogoutSuccessHandler logoutSuccessHandler;

	private final VaadinSavedRequestAwareAuthenticationSuccessHandler loginSuccessHandler;

	private final SessionRegistry sessionRegistry;

	private final BackChannelLogoutFilter backChannelLogoutFilter;

	/**
	 * Creates an instance of this configuration bean.
	 *
	 * @param properties                   the configuration properties
	 * @param sessionRegistry              the session registry
	 * @param clientRegistrationRepository the client-registration repository
	 * @param eventPublisher               the event-publisher
	 */
	public CustomSecurityConfig(SingleSignOnProperties properties, SessionRegistry sessionRegistry,
			ClientRegistrationRepository clientRegistrationRepository, ApplicationEventPublisher eventPublisher) {
		this.properties = properties;
		this.sessionRegistry = sessionRegistry;
		this.loginSuccessHandler = new VaadinSavedRequestAwareAuthenticationSuccessHandler();
		this.logoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
		this.logoutSuccessHandler.setRedirectStrategy(new UidlRedirectStrategy());
		this.backChannelLogoutFilter = new BackChannelLogoutFilter(sessionRegistry, clientRegistrationRepository,
				eventPublisher);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(auth -> auth.requestMatchers("/test/**").permitAll().anyRequest().authenticated());

		final var loginRoute = Objects.requireNonNullElse(properties.getLoginRoute(),
				SingleSignOnProperties.DEFAULT_LOGIN_ROUTE);
		final var logoutRedirectRoute = Objects.requireNonNullElse(properties.getLogoutRedirectRoute(),
				SingleSignOnProperties.DEFAULT_LOGOUT_REDIRECT_ROUTE);
		final var backChannelLogoutRoute = Objects.requireNonNullElse(properties.getBackChannelLogoutRoute(),
				SingleSignOnProperties.DEFAULT_BACKCHANNEL_LOGOUT_ROUTE);
		final var maximumSessions = properties.getMaximumConcurrentSessions();

		http.oauth2Login(oauth2Login -> {
			// Sets Vaadin's login success handler that makes login redirects
			// compatible with Hilla endpoints. This is otherwise done
			// VaadinWebSecurity::setLoginView which is not used for OIDC.
			var requestCache = http.getSharedObject(RequestCache.class);
			if (requestCache != null) {
				loginSuccessHandler.setRequestCache(requestCache);
			}
			oauth2Login.successHandler(loginSuccessHandler);

			// Permit all requests to the login route.
			oauth2Login.loginPage(loginRoute).permitAll();

			// Sets the login route as endpoint for redirection when
			// trying to access a protected view without authorization.
			getNavigationAccessControl().setLoginView(loginRoute);
		}).logout(logout -> {
			// Configures a logout success handler that takes care of closing
			// both the local user session and the OIDC provider remote session,
			// redirecting the web browser to the configured logout redirect
			// route when the process is completed.
			logoutSuccessHandler.setPostLogoutRedirectUri(logoutRedirectRoute);
			logout.logoutSuccessHandler(logoutSuccessHandler);
		}).exceptionHandling(exceptionHandling -> {
			// Sets the configured login route as the entry point to redirect
			// the web browser when an authentication exception is thrown.
			var entryPoint = new LoginUrlAuthenticationEntryPoint(loginRoute);
			exceptionHandling.authenticationEntryPoint(entryPoint);
		}).sessionManagement(sessionManagement -> {
			sessionManagement.sessionConcurrency(concurrency -> {
				// Sets the maximum number of concurrent sessions per user.
				// The default is -1 which means no limit on the number of
				// concurrent sessions per user.
				concurrency.maximumSessions(maximumSessions);

				// Sets the session-registry which is used for Back-Channel
				concurrency.sessionRegistry(sessionRegistry);

				// Sets the Vaadin-Refresh token to handle expired UIDL requests
				final var expiredStrategy = new UidlExpiredSessionStrategy();
				concurrency.expiredSessionStrategy(expiredStrategy);
			});
		});

		if (properties.isBackChannelLogout()) {
			backChannelLogoutFilter.setBackChannelLogoutRoute(backChannelLogoutRoute);

			// Adds the Back-Channel logout filter to the filter chain
			http.addFilterAfter(backChannelLogoutFilter, LogoutFilter.class);

			// Disable CSRF for Back-Channel logout requests
			final var matcher = backChannelLogoutFilter.getRequestMatcher();
			http.csrf().ignoringRequestMatchers(matcher);
		}
	}
}

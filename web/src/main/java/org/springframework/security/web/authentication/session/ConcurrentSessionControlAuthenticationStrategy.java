/*
 * Copyright 2002-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.authentication.session;

import java.util.Comparator;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.util.Assert;

/**
 * Strategy which handles concurrent session-control.
 *
 * <p>
 * When invoked following an authentication, it will check whether the user in question
 * should be allowed to proceed, by comparing the number of sessions they already have
 * active with the configured <tt>maximumSessions</tt> value. The {@link SessionRegistry}
 * is used as the source of data on authenticated users and session data.
 * </p>
 * <p>
 * If a user has reached the maximum number of permitted sessions, the behaviour depends
 * on the <tt>exceptionIfMaxExceeded</tt> property. The default behaviour is to expire any
 * sessions that exceed the maximum number of permitted sessions, starting with the least
 * recently used sessions. The expired sessions will be invalidated by the
 * {@link ConcurrentSessionFilter} if accessed again. If <tt>exceptionIfMaxExceeded</tt>
 * is set to <tt>true</tt>, however, the user will be prevented from starting a new
 * authenticated session.
 * </p>
 * <p>
 * This strategy can be injected into both the {@link SessionManagementFilter} and
 * instances of {@link AbstractAuthenticationProcessingFilter} (typically
 * {@link UsernamePasswordAuthenticationFilter}), but is typically combined with
 * {@link RegisterSessionAuthenticationStrategy} using
 * {@link CompositeSessionAuthenticationStrategy}.
 * </p>
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.2
 * @see CompositeSessionAuthenticationStrategy
 */
public class ConcurrentSessionControlAuthenticationStrategy
		implements MessageSourceAware, SessionAuthenticationStrategy {

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	private final SessionRegistry sessionRegistry;

	private boolean exceptionIfMaximumExceeded = false;

	private int maximumSessions = 1;

	/**
	 * @param sessionRegistry the session registry which should be updated when the
	 * authenticated session is changed.
	 */
	public ConcurrentSessionControlAuthenticationStrategy(SessionRegistry sessionRegistry) {
		Assert.notNull(sessionRegistry, "The sessionRegistry cannot be null");
		this.sessionRegistry = sessionRegistry;
	}

	/**
	 * In addition to the steps from the superclass, the sessionRegistry will be updated
	 * with the new session information.
	 */
	@Override
	public void onAuthentication(Authentication authentication, HttpServletRequest request,
			HttpServletResponse response) {
		int allowedSessions = getMaximumSessionsForThisUser(authentication);
		// TODO: 如果allowedSessions的值为-1 表示对session数量不做任何限制
		if (allowedSessions == -1) {
			// We permit unlimited logins
			return;
		}
		// TODO: 获取当前用户的所有的session, false表示不包含已经过期的session, 用户登录成功后，会将用户的sessionId存起来，其中key是用户的主体
		// TODO: value则是该主题对应的sessionId组成的集合
		List<SessionInformation> sessions = this.sessionRegistry.getAllSessions(authentication.getPrincipal(), false);
		// TODO: 接下来计算出当前的用户已经有几个有效地session了，同时获取允许的session并发数
		int sessionCount = sessions.size();
		// TODO: 如果当前session数 小于 session并发数(allowedSessions)，则不做处理，如果allowedSessions的值为-1,表示不限制
		if (sessionCount < allowedSessions) {
			// They haven't got too many login sessions running at present
			return;
		}
		// TODO: 如果当前session数 sessionCount等于session并发数，那么就先看看当前session是否不为null, 并且已经存在于sessions中了，如果已经存在了
		// TODO: 那就是自家人了，不做任何处理，如果当前session不为空，那么意味着将有一个新的session被创建出来，届时当前session数 sessionCount 就会超过session并发数 allowedSessions
		if (sessionCount == allowedSessions) {
			HttpSession session = request.getSession(false);
			if (session != null) {
				// Only permit it though if this request is associated with one of the
				// already registered sessions
				for (SessionInformation si : sessions) {
					// TODO: 如果已经存在于当前session中 直接return掉
					if (si.getSessionId().equals(session.getId())) {
						return;
					}
				}
			}
			// If the session is null, a new one will be created by the parent class,
			// exceeding the allowed number
			// TODO: 如果会话为空，则父类将创建一个新会话，超过允许的数量
		}
		allowableSessionsExceeded(sessions, allowedSessions, this.sessionRegistry);
	}

	/**
	 * Method intended for use by subclasses to override the maximum number of sessions
	 * that are permitted for a particular authentication. The default implementation
	 * simply returns the <code>maximumSessions</code> value for the bean.
	 * @param authentication to determine the maximum sessions for
	 * @return either -1 meaning unlimited, or a positive integer to limit (never zero)
	 */
	protected int getMaximumSessionsForThisUser(Authentication authentication) {
		return this.maximumSessions;
	}

	/**
	 * Allows subclasses to customise behaviour when too many sessions are detected.
	 * @param sessions either <code>null</code> or all unexpired sessions associated with
	 * the principal
	 * @param allowableSessions the number of concurrent sessions the user is allowed to
	 * have
	 * @param registry an instance of the <code>SessionRegistry</code> for subclass use
	 *
	 */
	protected void allowableSessionsExceeded(List<SessionInformation> sessions, int allowableSessions,
			SessionRegistry registry) throws SessionAuthenticationException {
		// TODO: exceptionIfMaximumExceeded 默认为false，可以配置成true，就直接抛出异常了，不允许多个session同时登陆
		if (this.exceptionIfMaximumExceeded || (sessions == null)) {
			throw new SessionAuthenticationException(
					this.messages.getMessage("ConcurrentSessionControlAuthenticationStrategy.exceededAllowed",
							new Object[] { allowableSessions }, "Maximum sessions of {0} for this principal exceeded"));
		}
		// Determine least recently used sessions, and mark them for invalidation
		// TODO: 对sessions按照请求时间进行排序，然后再使多余的session过期即可
		sessions.sort(Comparator.comparing(SessionInformation::getLastRequest));
		int maximumSessionsExceededBy = sessions.size() - allowableSessions + 1;
		// TODO: 使多余的session过期, 排完序后，最新的在后面，时间最大的在后面
		List<SessionInformation> sessionsToBeExpired = sessions.subList(0, maximumSessionsExceededBy);
		for (SessionInformation session : sessionsToBeExpired) {
			// TODO:
			session.expireNow();
		}
	}

	/**
	 * Sets the <tt>exceptionIfMaximumExceeded</tt> property, which determines whether the
	 * user should be prevented from opening more sessions than allowed. If set to
	 * <tt>true</tt>, a <tt>SessionAuthenticationException</tt> will be raised which means
	 * the user authenticating will be prevented from authenticating. if set to
	 * <tt>false</tt>, the user that has already authenticated will be forcibly logged
	 * out.
	 * @param exceptionIfMaximumExceeded defaults to <tt>false</tt>.
	 */
	public void setExceptionIfMaximumExceeded(boolean exceptionIfMaximumExceeded) {
		this.exceptionIfMaximumExceeded = exceptionIfMaximumExceeded;
	}

	/**
	 * Sets the <tt>maxSessions</tt> property. The default value is 1. Use -1 for
	 * unlimited sessions.
	 * @param maximumSessions the maximimum number of permitted sessions a user can have
	 * open simultaneously.
	 */
	public void setMaximumSessions(int maximumSessions) {
		Assert.isTrue(maximumSessions != 0,
				"MaximumLogins must be either -1 to allow unlimited logins, or a positive integer to specify a maximum");
		this.maximumSessions = maximumSessions;
	}

	/**
	 * Sets the {@link MessageSource} used for reporting errors back to the user when the
	 * user has exceeded the maximum number of authentications.
	 */
	@Override
	public void setMessageSource(MessageSource messageSource) {
		Assert.notNull(messageSource, "messageSource cannot be null");
		this.messages = new MessageSourceAccessor(messageSource);
	}

}

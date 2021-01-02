/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.web.context;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.core.log.LogMessage;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

/**
 *  TODO: 这是spring security默认的第二个过滤器
 *
 * Populates the {@link SecurityContextHolder} with information obtained from the
 * configured {@link SecurityContextRepository} prior to the request and stores it back in
 * the repository once the request has completed and clearing the context holder. By
 * default it uses an {@link HttpSessionSecurityContextRepository}. See this class for
 * information <tt>HttpSession</tt> related configuration options.
 * <p>
 * This filter will only execute once per request, to resolve servlet container
 * (specifically Weblogic) incompatibilities.
 * <p>
 * This filter MUST be executed BEFORE any authentication processing mechanisms.
 * Authentication processing mechanisms (e.g. BASIC, CAS processing filters etc) expect
 * the <code>SecurityContextHolder</code> to contain a valid <code>SecurityContext</code>
 * by the time they execute.
 * <p>
 * This is essentially a refactoring of the old
 * <tt>HttpSessionContextIntegrationFilter</tt> to delegate the storage issues to a
 * separate strategy, allowing for more customization in the way the security context is
 * maintained between requests.
 * <p>
 * The <tt>forceEagerSessionCreation</tt> property can be used to ensure that a session is
 * always available before the filter chain executes (the default is <code>false</code>,
 * as this is resource intensive and not recommended).
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class SecurityContextPersistenceFilter extends GenericFilterBean {

	static final String FILTER_APPLIED = "__spring_security_scpf_applied";

	private SecurityContextRepository repo;

	private boolean forceEagerSessionCreation = false;

	public SecurityContextPersistenceFilter() {
		this(new HttpSessionSecurityContextRepository());
	}

	public SecurityContextPersistenceFilter(SecurityContextRepository repo) {
		this.repo = repo;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
	}

	/**
	 * TODO: 默认的第二个拦截
	 *
	 * @param request
	 * @param response
	 * @param chain
	 * @throws IOException
	 * @throws ServletException
	 */
	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// ensure that filter is only applied once per request
		// TODO: 确保这个filter只执行了一次，去request上下文获取 __spring_security_scpf_applied 如果不为空，就说明已经走过这个方法了
		if (request.getAttribute(FILTER_APPLIED) != null) {
			// TODO: 直接走到下一个过滤器就好了
			chain.doFilter(request, response);
			return;
		}
		// TODO: 设置 FILTER_APPLIED 属性，表示已经过来这个过滤器了，然后下次判断直接就放行
		request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
		// TODO: 默认false
		if (this.forceEagerSessionCreation) {
			HttpSession session = request.getSession();
			if (this.logger.isDebugEnabled() && session.isNew()) {
				this.logger.debug(LogMessage.format("Created session %s eagerly", session.getId()));
			}
		}
		// TODO: 封装了request和response
		HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
		// TODO: 会尝试从httpSessionSecurityContextRepository中去加载context, 会尝试从session中加载，如果没有就创建一个空的
		// TODO: 维护了安全认证的用户信息
		SecurityContext contextBeforeChainExecution = this.repo.loadContext(holder);
		try {
			// TODO: 默认采用threadLocal的方式去存储securityContext，没有经过其他的过滤器链 contextBeforeChainExecution 这个可能是个空的
			// TODO: 这样就把从session中加载的用户认证信息拿到了，然后存到当前线程的threadLocal中
			SecurityContextHolder.setContext(contextBeforeChainExecution);
			if (contextBeforeChainExecution.getAuthentication() == null) {
				logger.debug("Set SecurityContextHolder to empty SecurityContext");
			}
			else {
				if (this.logger.isDebugEnabled()) {
					this.logger
							.debug(LogMessage.format("Set SecurityContextHolder to %s", contextBeforeChainExecution));
				}
			}
			// TODO: 接着往下执行其他的过滤器
			chain.doFilter(holder.getRequest(), holder.getResponse());
		}
		finally {
			// TODO: 最后执行完了其他的过滤器后，会执行到这里，拿出来被其他过滤器更改过后的securityContext
			SecurityContext contextAfterChainExecution = SecurityContextHolder.getContext();
			// Crucial removal of SecurityContextHolder contents before anything else.
			// TODO: 然后清空了securityContextHolder里面的内容，这一步是很重要的，因为清空ThreadLocal，防止其他线程拿到了security context信息，产生脏读
			SecurityContextHolder.clearContext();
			// TODO: 存储securityContext，存到sessiono中
			this.repo.saveContext(contextAfterChainExecution, holder.getRequest(), holder.getResponse());
			// TODO: 移除这个属性 __spring_security_scpf_applied ，已经执行完此过滤器了
			request.removeAttribute(FILTER_APPLIED);
			this.logger.debug("Cleared SecurityContextHolder to complete request");
		}
	}

	public void setForceEagerSessionCreation(boolean forceEagerSessionCreation) {
		this.forceEagerSessionCreation = forceEagerSessionCreation;
	}

}

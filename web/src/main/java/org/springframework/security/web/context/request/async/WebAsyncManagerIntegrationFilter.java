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

package org.springframework.security.web.context.request.async;

import java.io.IOException;
import java.util.concurrent.Callable;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.context.request.async.WebAsyncManager;
import org.springframework.web.context.request.async.WebAsyncUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * TODO: spring security 默认的第一个过滤器
 * Provides integration between the {@link SecurityContext} and Spring Web's
 * {@link WebAsyncManager} by using the
 * {@link SecurityContextCallableProcessingInterceptor#beforeConcurrentHandling(org.springframework.web.context.request.NativeWebRequest, Callable)}
 * to populate the {@link SecurityContext} on the {@link Callable}.
 *
 * @author Rob Winch
 * @see SecurityContextCallableProcessingInterceptor
 */
public final class WebAsyncManagerIntegrationFilter extends OncePerRequestFilter {

	private static final Object CALLABLE_INTERCEPTOR_KEY = new Object();

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// TODO: 从请求属性上获取所绑定的webAsyncManager, 如果尚未绑定，先做绑定
		WebAsyncManager asyncManager = WebAsyncUtils.getAsyncManager(request);
		// TODO: 从asyncManager中获取key为 CALLABLE_INTERCEPTOR_KEY 的SecurityContextCallableProcessingInterceptor，如果获取到的为Null
		// TODO: 说明其中还没有key为 CALLABLE_INTERCEPTOR_KEY 的SecurityContextCallableProcessingInterceptor,新建一个，并使用该key注册上去
		SecurityContextCallableProcessingInterceptor securityProcessingInterceptor = (SecurityContextCallableProcessingInterceptor) asyncManager
				.getCallableInterceptor(CALLABLE_INTERCEPTOR_KEY);
		// TODO: SecurityContextCallableProcessingInterceptor实现了 接口 CallableProcessingInterceptor，当它被应用于一次异步执行时
		// TODO: 它的方法beforeConcurrentHanding会在调用者线程执行，该方法会相应的从当前线程获取securityCOntext,然后被调用者线程执行设计的逻辑
		// TODO: 会使这个SecurityContext，从而实现上下文从调用者线程到被调用者线程的传播
		if (securityProcessingInterceptor == null) {
			asyncManager.registerCallableInterceptor(CALLABLE_INTERCEPTOR_KEY,
					new SecurityContextCallableProcessingInterceptor());
		}
		// TODO: 去执行下一个过滤器
		filterChain.doFilter(request, response);
	}

}

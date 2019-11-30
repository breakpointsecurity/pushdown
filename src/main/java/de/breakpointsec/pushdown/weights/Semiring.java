
package de.breakpointsec.pushdown.weights;

/*-
 * #%L
 * pushdown
 * %%
 * Copyright (C) 2019 Breakpoint Security GmbH
 * %%
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 * 
 * SPDX-License-Identifier: EPL-2.0
 * 
 * Copyright Breakpoint Security GmbH
 * #L%
 */

/**
 * A bounded idempotent semi-ring.
 */
public abstract class Semiring<T> {

	public abstract Semiring extendWith(Semiring other);

	public abstract Semiring combineWith(Semiring other);

	public abstract T value();

}

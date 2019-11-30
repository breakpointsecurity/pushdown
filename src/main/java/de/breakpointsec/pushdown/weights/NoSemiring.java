
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

public class NoSemiring extends Semiring {
	public static NoSemiring NO_WEIGHT_ONE = new NoSemiring();
	public static NoSemiring NO_WEIGHT_ZERO = new NoSemiring();

	@Override
	public Semiring extendWith(Semiring other) {
		return other;
	}

	@Override
	public Semiring combineWith(Semiring other) {
		return other;
	}

	@Override
	public Object value() {
		return "";
	}

	@Override
	public boolean equals(Object other) {
		if (other == null) {
			return false;
		}

		if (!(other instanceof NoSemiring)) {
			return false;
		}

		return this.value().equals(((NoSemiring) other).value());
	}
}

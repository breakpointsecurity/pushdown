
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

public class NumSemiring extends Semiring<Integer> {
	private int i;
	private static NumSemiring one;
	private static NumSemiring zero;

	public NumSemiring(int i) {
		this.i = i;
	}

	private NumSemiring() {
	}

	@Override
	public Semiring extendWith(Semiring other) {
		if (this.equals(one()))
			return other;
		if (other.equals(one()))
			return this;
		if (this.equals(zero()) || other.equals(zero()))
			return zero();
		NumSemiring o = (NumSemiring) other;
		return new NumSemiring(o.i + i);
	}

	@Override
	public Semiring combineWith(Semiring other) {
		if (other.equals(zero()))
			return this;
		if (this.equals(zero()))
			return other;
		NumSemiring o = (NumSemiring) other;
		if (o.i == i)
			return o;
		return zero();
	}

	@Override
	public Integer value() {
		return this.i;
	}

	public static <N> NumSemiring one() {
		if (one == null) {
			one = new NumSemiring() {
				@Override
				public String toString() {
					return "<ONE>";
				}

				@Override
				public boolean equals(Object obj) {
					return obj == this;
				}
			};
		}
		return one;
	}

	public static <N> NumSemiring zero() {
		if (zero == null)
			zero = new NumSemiring() {
				@Override
				public String toString() {
					return "<ZERO>";
				}

				@Override
				public boolean equals(Object obj) {
					return obj == this;
				}
			};
		return zero;
	}

	@Override
	public String toString() {
		return Integer.toString(i);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + i;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		NumSemiring other = (NumSemiring) obj;
		if (i != other.i)
			return false;
		return true;
	}

}

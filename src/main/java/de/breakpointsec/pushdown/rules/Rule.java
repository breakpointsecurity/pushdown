
package de.breakpointsec.pushdown.rules;

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

import de.breakpointsec.pushdown.Configuration;

public abstract class Rule<Location, State, Weight> {
	protected Location l1;
	protected State s1;
	protected Location l2;
	protected State s2;
	protected Weight w;

	public Rule(State s1, Location l1, State s2, Location l2, Weight w) {
		this.l1 = l1;
		this.s1 = s1;
		this.l2 = l2;
		this.s2 = s2;
		this.w = w;
	}

	public Configuration<Location, State> getStartConfig() {
		return new Configuration<Location, State>(l1, s1);
	}

	public Configuration<Location, State> getTargetConfig() {
		return new Configuration<Location, State>(l2, s2);
	}

	public Location getL1() {
		return l1;
	}

	public Location getL2() {
		return l2;
	}

	public State getS1() {
		return s1;
	}

	public State getS2() {
		return s2;
	}

	public void setS1(State s1) {
		this.s1 = s1;
	}

	public Weight getWeight() {
		return w;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((l1 == null) ? 0 : l1.hashCode());
		result = prime * result + ((l2 == null) ? 0 : l2.hashCode());
		result = prime * result + ((s1 == null) ? 0 : s1.hashCode());
		result = prime * result + ((s2 == null) ? 0 : s2.hashCode());
		result = prime * result + ((w == null) ? 0 : w.hashCode());
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
		Rule other = (Rule) obj;
		if (l1 == null) {
			if (other.l1 != null)
				return false;
		} else if (!l1.equals(other.l1))
			return false;
		if (l2 == null) {
			if (other.l2 != null)
				return false;
		} else if (!l2.equals(other.l2))
			return false;
		if (s1 == null) {
			if (other.s1 != null)
				return false;
		} else if (!s1.equals(other.s1))
			return false;
		if (s2 == null) {
			if (other.s2 != null)
				return false;
		} else if (!s2.equals(other.s2))
			return false;
		if (w == null) {
			if (other.w != null)
				return false;
		} else if (!w.equals(other.w))
			return false;
		return true;
	}

}

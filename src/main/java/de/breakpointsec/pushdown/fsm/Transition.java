
package de.breakpointsec.pushdown.fsm;

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

public class Transition<Loc, State> {
	private final State s1;
	private final Loc l1;
	private final State s2;
	private int hashCode;

	public Transition(State s1, Loc l1, State s2) {
		assert s1 != null;
		assert s2 != null;
		assert l1 != null;
		this.s1 = s1;
		this.l1 = l1;
		this.s2 = s2;
	}

	public Configuration<Loc, State> getStartConfig() {
		return new Configuration<Loc, State>(l1, s1);
	}

	public State getTarget() {
		return s2;
	}

	public State getStart() {
		return s1;
	}

	public Loc getString() {
		return l1;
	}

	@Override
	public int hashCode() {
		if (hashCode != 0)
			return hashCode;
		final int prime = 31;
		int result = 1;
		result = prime * result + ((l1 == null) ? 0 : l1.hashCode());
		result = prime * result + ((s1 == null) ? 0 : s1.hashCode());
		result = prime * result + ((s2 == null) ? 0 : s2.hashCode());
		hashCode = result;
		return hashCode;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Transition other = (Transition) obj;
		if (l1 == null) {
			if (other.l1 != null)
				return false;
		} else if (!l1.equals(other.l1))
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
		return true;
	}

	@Override
	public String toString() {
		return s1 + " ~" + l1 + "~> " + s2;
	}

	public Loc getLabel() {
		return l1;
	}
}

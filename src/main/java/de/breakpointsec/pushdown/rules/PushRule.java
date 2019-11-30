
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

public class PushRule<Location, State, Weight> extends Rule<Location, State, Weight> {

	protected Location callSite;

	public PushRule(State s1, Location l1, State s2, Location l2, Location callSite, Weight w) {
		super(s1, l1, s2, l2, w);
		this.callSite = callSite;
	}

	public Location getCallSite() {
		return callSite;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((callSite == null) ? 0 : callSite.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		PushRule other = (PushRule) obj;
		if (callSite == null) {
			if (other.callSite != null)
				return false;
		} else if (!callSite.equals(other.callSite))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "<" + s1 + ";" + l1 + ">-><" + s2 + ";" + l2 + "." + callSite + ">(" + w + ")";
	}
}

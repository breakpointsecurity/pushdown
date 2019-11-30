
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

public class PopRule<Location, State, Weight> extends Rule<Location, State, Weight> {

	public PopRule(State s1, Location l1, State s2, Weight w) {
		super(s1, l1, s2, null, w);
	}

	@Override
	public String toString() {
		return "<" + s1 + ";" + l1 + ">-><" + s2 + ">(" + w + ")";
	}
}

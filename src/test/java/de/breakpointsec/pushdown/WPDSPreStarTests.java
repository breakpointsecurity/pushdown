/*******************************************************************************
 * Copyright (c) 2018 Fraunhofer IEM, Paderborn, Germany.
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     Johannes Spaeth - initial API and implementation
 *******************************************************************************/

package de.breakpointsec.pushdown;

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

import de.breakpointsec.pushdown.fsm.WeightedAutomaton;
import de.breakpointsec.pushdown.weights.Semiring;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class WPDSPreStarTests extends GenericPDSTest {
	private WPDS<StackSymbol, Configuration, Semiring> pds;

	@Before
	public void init() {
		pds = new WPDS<StackSymbol, Configuration, Semiring>() {
			@Override
			public StackSymbol epsilon() {
				return new StackSymbol("eps");
			}
		};
	}

	@Test
	public void simple() throws IllegalTransitionException {
		pds.addRule(normal(1, "a", 2, "b", w(2)));
		pds.addRule(normal(2, "b", 3, "c", w(3)));
		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = waccepts(3, "c", w(0));
		pds.prestar(fa);
		System.out.println(fa.toDotString());
		assertEquals(fa.getTransitions().size(), 3);
		assertEquals(fa.getStates().size(), 4);
		assertEquals(fa.getWeightFor(t(1, "a", ACCEPT)), w(5));
	}

	@Test
	public void simpleNoAccept() throws IllegalTransitionException {
		// Policy (as FSA)
		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = waccepts(Status.INIT.v(), "open", w(0));
		fa.addTransition(t(Status.INIT.v(), "open", Status.OPEN.v()));
		fa.addTransition(t(Status.OPEN.v(), "close", Status.CLOSED.v()));

		// Program
		pds.addRule(normal(Status.INIT.v(), "m1.open", Status.OPEN.v(), "m1.do_something", w(2)));
		pds.addRule(push(Status.INIT.v(), "m1.call_m2", Status.INIT.v(), "open", "m1.continue_in_m1", w(2)));
		pds.addRule(normal(Status.INIT.v(), "open", Status.OPEN.v(), "return", w(3)));
		pds.addRule(pop(Status.OPEN.v(), "return", Status.OPEN.v(), w(3)));
		pds.addRule(normal(Status.OPEN.v(), "close", Status.CLOSED.v(), "end", w(3)));

		pds.prestar(fa);
		System.out.println(fa.toDotString());
	}

	@Test
	public void branch() throws IllegalTransitionException {
		pds.addRule(normal(1, "a", 1, "b", w(2)));
		pds.addRule(normal(1, "b", 1, "c", w(4)));
		pds.addRule(normal(1, "a", 1, "d", w(3)));
		pds.addRule(normal(1, "d", 1, "c", w(3)));
		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = waccepts(1, "c", w(0));
		pds.prestar(fa);
		System.out.println(fa);
		assertEquals(fa.getWeightFor(t(1, "a", ACCEPT)), w(6));
		assertEquals(fa.getWeightFor(t(1, "b", ACCEPT)), w(4));
		assertEquals(fa.getWeightFor(t(1, "d", ACCEPT)), w(3));
	}

	@Test
	public void push1() throws IllegalTransitionException {
		pds.addRule(normal(1, "a", 1, "b", w(2)));
		pds.addRule(push(1, "b", 1, "c", "d", w(3)));
		pds.addRule(normal(1, "c", 1, "e", w(1)));
		pds.addRule(pop(1, "e", 1, w(5)));
		pds.addRule(normal(1, "d", 1, "f", w(6)));
		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = waccepts(1, "f", w(0));
		pds.prestar(fa);
		System.out.println(fa);
		assertEquals(fa.getWeightFor(t(1, "a", ACCEPT)), w(17));
		assertEquals(fa.getWeightFor(t(1, "b", ACCEPT)), w(15));
		assertEquals(fa.getWeightFor(t(1, "c", 1)), w(6));
	}

	public enum Status {
		INIT(0), OPEN(1), CLOSED(2);

		private final int value;

		Status(int i) {
			this.value = i;
		}

		public int v() {
			return this.value;
		}

	}
}

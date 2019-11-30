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

import de.breakpointsec.pushdown.IllegalTransitionException;
import de.breakpointsec.pushdown.fsm.Transition;
import de.breakpointsec.pushdown.fsm.WeightedAutomaton;
import de.breakpointsec.pushdown.weights.NumSemiring;
import de.breakpointsec.pushdown.weights.Semiring;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class WPDSPostStarTest extends GenericPDSTest {
	private WPDS<StackSymbol, Configuration, Semiring> pds;

	@Before
	public void init() {
		pds = new WPDS<StackSymbol, Configuration, Semiring>() {
			@Override
			public StackSymbol epsilon() {
				return new StackSymbol("EPS");
			}
		};
	}

	@Test
	public void simpleDataflowAccept() throws IllegalTransitionException {
		/*
		 * Control locations of the PDS refer to program variables. Stack alphabet of the PDS refers to program statements.
		 */

		/*
		 * Program: String x = 'bla' String y = x String result = doBlubb(y) doBlubb(z): return z
		 */
		pds.addRule(normal(1, "String x = 'bla'", 1, "String y = x", w(1))); // Flow remains in x
		pds.addRule(normal(1, "String x = 'bla'", 2, "String y = x", w(1))); // Flow applies to y
		pds.addRule(push(2, "String y = x", 11, "return z", "String result = doBlubb(y)", w(8))); // Flow from y to z in doBlubb
		pds.addRule(pop(11, "return z", 3, w(1))); // blubb in doBlubb is assigned to result
		pds.addRule(pop(2, "return z", 3, w(1))); // z in doBlubb is assigned to y

		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = waccepts(1, "String x = 'bla'", w(1));

		System.out.println("post*-automaton describing all points-to variables for the initial configuration (x, String x = 'bla')\n");
		pds.poststar(fa);
		System.out.println(fa.toDotString());
	}

	@Test
	public void simple() throws IllegalTransitionException {
		pds.addRule(normal(1, "a", 2, "b", w(2)));
		pds.addRule(normal(2, "b", 3, "c", w(3)));

		System.out.println(pds.toString());

		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = waccepts(1, "a", w(0));
		System.out.println(fa.toDotString());
		pds.poststar(fa);
		System.out.println(fa.toDotString());
		assertEquals(fa.getTransitions().size(), 3);
		assertEquals(fa.getStates().size(), 4);
		assertEquals(fa.getWeightFor(t(3, "c", ACCEPT)), w(5));

		assertFalse(fa.containsLoop());
	}

	@Test
	public void branch() throws IllegalTransitionException {
		pds.addRule(normal(1, "a", 1, "b", w(2)));
		pds.addRule(normal(1, "b", 1, "c", w(3)));
		pds.addRule(normal(1, "a", 1, "d", w(3)));
		pds.addRule(normal(1, "d", 1, "c", w(3)));
		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = waccepts(1, "a", w(0));
		pds.poststar(fa);
		System.out.println(fa);
		assertEquals(fa.getWeightFor(t(1, "c", ACCEPT)), NumSemiring.zero());
		assertEquals(fa.getWeightFor(t(1, "b", ACCEPT)), w(2));
		assertEquals(fa.getWeightFor(t(1, "d", ACCEPT)), w(3));
	}

	@Test
	@Ignore // This test fails also in the original implementation of Späth et al.
	public void push1() throws IllegalTransitionException {
		pds.addRule(normal(1, "a", 1, "b", w(2)));
		pds.addRule(push(1, "b", 1, "c", "d", w(3)));
		pds.addRule(normal(1, "c", 1, "e", w(1)));
		pds.addRule(pop(1, "e", 1, w(5)));
		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = waccepts(1, "a", w(0));
		pds.poststar(fa);
		System.out.println(fa);
		assertEquals(fa.getWeightFor(t(1, "b", ACCEPT)), w(2));
		assertEquals(fa.getWeightFor(t(1, "d", ACCEPT)), w(11));
		assertEquals(fa.getWeightFor(t(1, "e", a(1, "c"))), w(1));
		Map<Transition<StackSymbol, Configuration>, Semiring> weights = fa.getTransitionsToFinalWeights();
		System.out.println(weights);
		assertEquals(weights.get(t(1, "e", a(1, "c"))), w(6));

	}

	@Test
	public void push2() throws IllegalTransitionException {
		pds.addRule(normal(1, "a", 2, "b", w(2)));
		pds.addRule(push(2, "b", 3, "c", "d", w(3)));
		pds.addRule(normal(3, "c", 4, "e", w(1)));
		pds.addRule(pop(4, "e", 5, w(5)));
		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = waccepts(1, "a", w(0));
		pds.poststar(fa);
		System.out.println(fa);
		assertEquals(fa.getWeightFor(t(5, "d", ACCEPT)), w(11));
	}

	@Test
	public void twoCall() throws IllegalTransitionException {
		pds.addRule(normal(1, "a", 1, "b", w(1)));
		pds.addRule(push(1, "b", 2, "call", "d", w(2)));
		pds.addRule(normal(2, "call", 2, "e", w(3)));
		pds.addRule(pop(2, "e", 3, w(4)));
		pds.addRule(normal(3, "d", 1, "f", w(5)));
		pds.addRule(push(1, "f", 2, "call", "g", w(6)));
		pds.addRule(normal(3, "g", 4, "h", w(7)));
		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = waccepts(1, "a", w(0));
		pds.poststar(fa);
		System.out.println(fa);
		System.out.println(fa.toDotString());
		assertEquals(w(15), fa.getWeightFor(t(1, "f", ACCEPT)));
		assertEquals(w(7), fa.getWeightFor(t(3, fa.epsilon(), a(2, "call"))));
		assertEquals(w(10), fa.getWeightFor(t(3, "d", ACCEPT)));

		assertEquals(w(28), fa.getWeightFor(t(3, "g", ACCEPT)));
		assertEquals(w(35), fa.getWeightFor(t(4, "h", ACCEPT)));
	}

	@Test
	public void oneCall() throws IllegalTransitionException {
		pds.addRule(normal(1, "a", 1, "b", w(1)));
		pds.addRule(push(1, "b", 2, "call", "d", w(2)));
		pds.addRule(normal(2, "call", 2, "e", w(3)));
		pds.addRule(pop(2, "e", 3, w(4)));
		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = waccepts(1, "a", w(0));
		System.out.println(fa);
		pds.poststar(fa);
		System.out.println(fa);
		assertEquals(w(10), fa.getWeightFor(t(3, "d", ACCEPT)));
	}

	@Test
	public void twoCallOnlyReturnWeight() throws IllegalTransitionException {
		pds.addRule(normal(1, "a", 1, "b", w(0)));
		pds.addRule(push(1, "b", 2, "call", "d", w(0)));
		pds.addRule(normal(2, "call", 2, "e", w(0)));
		pds.addRule(pop(2, "e", 3, w(4)));
		pds.addRule(normal(3, "d", 3, "f", w(0)));
		pds.addRule(push(3, "f", 2, "call", "g", w(0)));
		pds.addRule(normal(3, "g", 4, "h", w(0)));
		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = waccepts(1, "a", w(0));
		pds.poststar(fa);
		System.out.println(fa);
		assertEquals(w(4), fa.getWeightFor(t(3, "f", ACCEPT)));
		assertEquals(w(8), fa.getWeightFor(t(3, "g", ACCEPT)));
		assertEquals(w(8), fa.getWeightFor(t(4, "h", ACCEPT)));
	}
}


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

import de.breakpointsec.pushdown.fsm.Transition;
import de.breakpointsec.pushdown.fsm.WeightedAutomaton;
import de.breakpointsec.pushdown.weights.NoSemiring;
import de.breakpointsec.pushdown.weights.Semiring;
import org.junit.Before;
import org.junit.Test;

import java.util.Collection;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class PrestarTest extends GenericPDSTest {

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
		pds.addRule(normal(1, "1", 1, "2", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(normal(1, "2", 1, "3", NoSemiring.NO_WEIGHT_ZERO));
		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = accepts(1, "3", NoSemiring.NO_WEIGHT_ZERO);
		pds.prestar(fa);
		assertEquals(fa.getTransitions().size(), 3);
		assertEquals(fa.getStates().size(), 2);
		assertTrue(fa.getStates().contains(a(1)));
	}

	@Test
	public void simple2() throws IllegalTransitionException {
		pds.addRule(normal(1, "a", 2, "b", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(normal(2, "b", 2, "c", NoSemiring.NO_WEIGHT_ZERO));
		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = accepts(2, "c", NoSemiring.NO_WEIGHT_ZERO);
		pds.prestar(fa);
		assertEquals(fa.getTransitions().size(), 3);
		assertEquals(fa.getStates().size(), 3);
		assertTrue(fa.getStates().contains(a(1)));
		assertTrue(fa.getStates().contains(a(2)));
	}

	@Test
	public void pushTest() throws IllegalTransitionException {
		pds.addRule(normal(1, "a", 1, "b", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(push(1, "b", 1, "c", "d", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(pop(1, "c", 1, NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(normal(1, "d", 1, "e", NoSemiring.NO_WEIGHT_ZERO));
		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = accepts(1, "e", NoSemiring.NO_WEIGHT_ZERO);
		pds.prestar(fa);
		assertTrue(fa.getTransitions().contains(t(1, "c", 1)));
		assertTrue(fa.getTransitions().contains(t(1, "a", ACCEPT)));
	}

	@Test
	public void doublePushTest() throws IllegalTransitionException {
		pds.addRule(normal(1, "a", 1, "b", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(normal(1, "b", 1, "c", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(push(1, "c", 1, "d", "e", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(push(1, "d", 1, "h", "i", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(pop(1, "h", 1, NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(pop(1, "d", 1, NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(normal(1, "e", 1, "k", NoSemiring.NO_WEIGHT_ZERO));
		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = accepts(1, "k", NoSemiring.NO_WEIGHT_ZERO);
		pds.prestar(fa);
		System.out.println(fa);
		assertTrue(fa.getTransitions().contains(t(1, "k", ACCEPT)));
		fa = accepts(1, "k", NoSemiring.NO_WEIGHT_ZERO);
		pds.prestar(fa);
		assertTrue(fa.getTransitions().contains(t(1, "a", ACCEPT)));
	}

	@Test
	public void recPushTest() throws IllegalTransitionException {
		pds.addRule(normal(1, "a", 1, "b", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(normal(1, "b", 1, "c", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(push(1, "c", 1, "d", "e", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(normal(1, "d", 1, "f", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(push(1, "f", 1, "d", "h", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(pop(1, "d", 1, NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(normal(1, "e", 1, "k", NoSemiring.NO_WEIGHT_ZERO));
		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = accepts(1, "k", NoSemiring.NO_WEIGHT_ZERO);
		pds.prestar(fa);
		System.out.println(fa);
		assertTrue(fa.getTransitions().contains(t(1, "c", ACCEPT)));
		assertTrue(fa.getTransitions().contains(t(1, "a", ACCEPT)));
	}

	@Test
	public void recPushTestSimple() throws IllegalTransitionException {
		pds.addRule(push(1, "a", 1, "d", "e", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(push(1, "d", 1, "d", "h", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(pop(1, "d", 1, NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(normal(1, "e", 1, "k", NoSemiring.NO_WEIGHT_ZERO));
		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = accepts(1, "k", NoSemiring.NO_WEIGHT_ZERO);
		pds.prestar(fa);
		assertTrue(fa.getTransitions().contains(t(1, "a", ACCEPT)));
	}

	// Example taken from http://research.cs.wisc.edu/wpis/papers/fsttcs07.invited.pdf
	@Test
	public void paperEx() throws IllegalTransitionException {
		pds.addRule(normal(1, "n1", 1, "n2", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(normal(1, "n1", 1, "n3", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(push(1, "n2", 1, "n7", "n4", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(push(1, "n3", 1, "n7", "n5", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(normal(1, "n4", 1, "n6", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(normal(1, "n5", 1, "n6", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(normal(1, "n7", 1, "n8", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(pop(1, "n8", 1, NoSemiring.NO_WEIGHT_ZERO));
		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = accepts(1, "n6", NoSemiring.NO_WEIGHT_ZERO);
		pds.prestar(fa);
		System.out.println(fa);
		System.out.println(fa.toDotString());
		Collection<Transition<StackSymbol, Configuration>> transitions = fa.getTransitions();
		transitions.remove(t(1, "n1", ACCEPT));
		transitions.remove(t(1, "n2", ACCEPT));
		transitions.remove(t(1, "n3", ACCEPT));
		transitions.remove(t(1, "n4", ACCEPT));
		transitions.remove(t(1, "n5", ACCEPT));
		transitions.remove(t(1, "n6", ACCEPT));
		transitions.remove(t(1, "n7", 1));
		transitions.remove(t(1, "n8", 1));
		assertTrue(transitions.isEmpty());
	}

}

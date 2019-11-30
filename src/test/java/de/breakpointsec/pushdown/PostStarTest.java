
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
import de.breakpointsec.pushdown.weights.NoSemiring;
import de.breakpointsec.pushdown.weights.Semiring;
import org.junit.Before;
import org.junit.Test;

import java.util.Collection;
import java.util.stream.Collectors;

import static org.junit.Assert.assertTrue;

public class PostStarTest extends GenericPDSTest {

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
	public void popEpsilonTest1() throws IllegalTransitionException {
		pds.addRule(push(2, "b", 2, "c", "d", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(pop(3, "c", 3, NoSemiring.NO_WEIGHT_ZERO));

		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = accepts(2, "b", NoSemiring.NO_WEIGHT_ZERO);
		fa.addTransition(new Transition<StackSymbol, Configuration>(a(3), fa.epsilon(), a(2)));
		pds.poststar(fa);
		System.out.println(fa.getTransitions());
		assertTrue(fa.getTransitions().contains(t(3, "EPS", 2)));
		assertTrue(fa.getTransitions().contains(t(2, "b", ACCEPT)));
	}

	@Test
	public void popEpsilonTest() throws IllegalTransitionException {
		pds.addRule(push(1, "b", 1, "c", "d", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(pop(1, "c", 1, NoSemiring.NO_WEIGHT_ZERO));
		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = accepts(1, "b", NoSemiring.NO_WEIGHT_ZERO);
		fa.addTransition(new Transition<StackSymbol, Configuration>(a(0), fa.epsilon(), a(1)));
		System.out.println(String.join("\n", fa.getTransitions().stream().map(t -> t.toString()).collect(Collectors.toList())));
		System.out.println("-----------------");
		pds.poststar(fa);
		System.out.println(String.join("\n", fa.getTransitions().stream().map(t -> t.toString()).collect(Collectors.toList())));
		assertTrue(fa.getTransitions().contains(t(1, "d", ACCEPT)));
		assertTrue(fa.getTransitions().contains(t(0, fa.epsilon().toString(), 1)));
	}

	@Test
	public void pushTest() throws IllegalTransitionException {
		pds.addRule(normal(1, "a", 1, "b", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(push(1, "b", 1, "c", "d", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(pop(1, "c", 1, NoSemiring.NO_WEIGHT_ZERO));
		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = accepts(1, "a", NoSemiring.NO_WEIGHT_ZERO);
		pds.poststar(fa);
		System.out.println(fa);
		assertTrue(fa.getTransitions().contains(t(1, "d", ACCEPT)));
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
		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = accepts(1, "a", NoSemiring.NO_WEIGHT_ZERO);
		pds.poststar(fa);
		System.out.println(fa);
		assertTrue(fa.getTransitions().contains(t(1, "k", ACCEPT)));
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
		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = accepts(1, "a", NoSemiring.NO_WEIGHT_ZERO);
		pds.poststar(fa);
		assertTrue(fa.getTransitions().contains(t(1, "k", ACCEPT)));
		assertTrue(fa.getTransitions().contains(t(1, "k", ACCEPT)));
		assertTrue(fa.getTransitions().contains(t(1, fa.epsilon(), new Configuration(a(1), s("d")))));
	}

	@Test
	public void recPushTestSimple() throws IllegalTransitionException {
		pds.addRule(push(1, "a", 1, "d", "e", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(push(1, "d", 1, "d", "h", NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(pop(1, "d", 1, NoSemiring.NO_WEIGHT_ZERO));
		pds.addRule(normal(1, "e", 1, "k", NoSemiring.NO_WEIGHT_ZERO));
		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = accepts(1, "a", NoSemiring.NO_WEIGHT_ZERO);
		pds.poststar(fa);
		Collection<Transition<StackSymbol, Configuration>> transitions = fa.getTransitions();
		transitions.remove(t(1, "e", ACCEPT));
		transitions.remove(t(1, "a", ACCEPT));
		transitions.remove(t(1, "k", ACCEPT));
		transitions.remove(t(a(1, "d"), "e", ACCEPT));
		transitions.remove(t(a(1, "d"), s("h"), a(1, "d")));
		transitions.remove(t(1, s("d"), a(1, "d")));
		transitions.remove(t(1, s("h"), a(1, "d")));
		transitions.remove(t(1, fa.epsilon(), a(1, "d")));
		assertTrue(transitions.isEmpty());
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
		WeightedAutomaton<StackSymbol, Configuration, Semiring> fa = accepts(1, "n1", NoSemiring.NO_WEIGHT_ZERO);
		pds.poststar(fa);
		Collection<Transition<StackSymbol, Configuration>> transitions = fa.getTransitions();
		System.out.println(String.join("\n", transitions.stream().map(t -> t.toString()).collect(Collectors.toList())));
		System.out.println(".................");
		transitions.remove(t(1, "n1", ACCEPT));
		transitions.remove(t(1, "n2", ACCEPT));
		transitions.remove(t(1, "n3", ACCEPT));
		transitions.remove(t(1, "n4", ACCEPT));
		transitions.remove(t(1, "n5", ACCEPT));
		transitions.remove(t(1, "n6", ACCEPT));
		transitions.remove(t(1, fa.epsilon(), a(1, "n7")));
		transitions.remove(t(1, "n7", a(1, "n7")));
		transitions.remove(t(1, "n8", a(1, "n7")));
		transitions.remove(t(a(1, "n7"), "n4", ACCEPT));
		transitions.remove(t(a(1, "n7"), "n5", ACCEPT));
		System.out.println(String.join("\n", transitions.stream().map(t -> t.toString()).collect(Collectors.toList())));
		assertTrue(transitions.isEmpty());
	}
}

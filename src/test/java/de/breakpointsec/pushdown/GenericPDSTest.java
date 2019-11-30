
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
import de.breakpointsec.pushdown.rules.NormalRule;
import de.breakpointsec.pushdown.rules.PopRule;
import de.breakpointsec.pushdown.rules.PushRule;
import de.breakpointsec.pushdown.weights.NoSemiring;
import de.breakpointsec.pushdown.weights.NumSemiring;
import de.breakpointsec.pushdown.weights.Semiring;

public class GenericPDSTest {

	static Configuration ACCEPT = a(999);

	static WeightedAutomaton<StackSymbol, Configuration, Semiring> accepts(int a, String c, Semiring semiring) {
		WeightedAutomaton<StackSymbol, Configuration, Semiring> aut = new WeightedAutomaton<StackSymbol, Configuration, Semiring>(
			a(a)) {

			@Override
			public Configuration createState(Configuration d, StackSymbol loc) {
				return new Configuration(d, loc);
			}

			@Override
			public StackSymbol epsilon() {
				return s("EPS");
			}

			@Override
			public Semiring getOne() {
				return NoSemiring.NO_WEIGHT_ZERO;
			}

			@Override
			public Semiring getZero() {
				return NoSemiring.NO_WEIGHT_ZERO;
			}

			@Override
			public boolean isGeneratedState(Configuration d) {
				return d.s != null;
			}
		};
		aut.addFinalState(ACCEPT);
		aut.addTransition(t(a, c, ACCEPT));
		aut.combineWeightForTransition(t(a, c, ACCEPT), semiring);
		return aut;
	}

	static WeightedAutomaton<StackSymbol, Configuration, Semiring> waccepts(int a, String c, Semiring semiring) {
		WeightedAutomaton<StackSymbol, Configuration, Semiring> aut = new WeightedAutomaton<StackSymbol, Configuration, Semiring>(
			a(a)) {

			@Override
			public Configuration createState(Configuration d, StackSymbol loc) {
				return new Configuration(d, loc);
			}

			@Override
			public StackSymbol epsilon() {
				return s("EPS");
			}

			@Override
			public Semiring getOne() {
				return NumSemiring.one();
			}

			@Override
			public Semiring getZero() {
				return NumSemiring.zero();
			}

			@Override
			public boolean isGeneratedState(Configuration d) {
				return d.s != null;
			}
		};
		aut.addFinalState(ACCEPT);
		aut.addTransition(t(a, c, ACCEPT));
		aut.combineWeightForTransition(t(a, c, ACCEPT), semiring);
		return aut;
	}

	static Configuration a(int a) {
		return new Configuration(a);
	}

	static Configuration a(int a, String b) {
		return new Configuration(a(a), s(b));
	}

	static StackSymbol s(String a) {
		return new StackSymbol(a);
	}

	static Transition<StackSymbol, Configuration> t(Configuration a, StackSymbol c, Configuration b) {
		return new Transition<StackSymbol, Configuration>(a, c, b);
	}

	static Transition<StackSymbol, Configuration> t(Configuration a, String c, Configuration b) {
		return new Transition<StackSymbol, Configuration>(a, s(c), b);
	}

	static Transition<StackSymbol, Configuration> t(int a, StackSymbol c, Configuration b) {
		return t(a(a), c, b);
	}

	static Transition<StackSymbol, Configuration> t(int a, String c, Configuration b) {
		return t(a, s(c), b);
	}

	static Transition<StackSymbol, Configuration> t(int a, String c, int b) {
		return t(a, c, a(b));
	}

	static NormalRule<StackSymbol, Configuration, Semiring> normal(int a, String n, int b, String m, Semiring w) {
		return new NormalRule<StackSymbol, Configuration, Semiring>(a(a), s(n), a(b), s(m), w);
	}

	static PushRule<StackSymbol, Configuration, Semiring> push(int a, String n, int b, String m, String callSite, Semiring w) {
		return new PushRule<StackSymbol, Configuration, Semiring>(a(a), s(n), a(b), s(m), s(callSite), w);
	}

	static PopRule<StackSymbol, Configuration, Semiring> pop(int a, String n, int b, Semiring w) {
		return new PopRule<StackSymbol, Configuration, Semiring>(a(a), s(n), a(b), w);
	}

	static NumSemiring w(int i) {
		return new NumSemiring(i);
	}

	static class Configuration {
		final int a;
		final StackSymbol s;

		Configuration(int a) {
			this.a = a;
			this.s = null;
		}

		Configuration(Configuration a, StackSymbol s) {
			this.s = s;
			this.a = a.a;
		}

		@Override
		public String toString() {
			return (s == null ? Integer.toString(a) : "<" + a + "," + s + ">");
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + a;
			result = prime * result + ((s == null) ? 0 : s.hashCode());
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
			Configuration other = (Configuration) obj;
			if (a != other.a)
				return false;
			if (s == null) {
				if (other.s != null)
					return false;
			} else if (!s.equals(other.s))
				return false;
			return true;
		}

	}

	static class StackSymbol {
		String s;

		StackSymbol(String s) {
			this.s = s;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((s == null) ? 0 : s.hashCode());
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
			StackSymbol other = (StackSymbol) obj;
			if (s == null) {
				if (other.s != null)
					return false;
			} else if (!s.equals(other.s))
				return false;
			return true;
		}

		@Override
		public String toString() {
			return s;
		}
	}
}


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

import java.util.HashSet;
import java.util.Set;

public class DataFlowPathSemiring<Statement> extends Semiring<String> {

	private static DataFlowPathSemiring one;
	private static DataFlowPathSemiring zero;

	/**
	 * This set keeps track of all statement that use an alias from source to sink.
	 */
	private Set<Statement> allStatements;

	/**
	 * A subset of {@link #allStatements} that lists only the last usage of a variable. When data-flow at branches is joined, the set can contain multiple statement that
	 * use the variable
	 */
	private Set<Statement> lastStatements;

	private String rep;

	private DataFlowPathSemiring(String rep) {
		this.rep = rep;
	}

	private DataFlowPathSemiring(Set<Statement> allStatement, Set<Statement> lastStatements) {
		this.allStatements = allStatement;
		this.lastStatements = lastStatements;
	}

	public DataFlowPathSemiring(Statement relevantStatement) {
		allStatements = new HashSet<>();
		lastStatements = new HashSet<>();
		allStatements.add(relevantStatement);
		lastStatements.add(relevantStatement);
	}

	@Override
	public Semiring extendWith(Semiring o) {
		if (!(o instanceof DataFlowPathSemiring))
			throw new RuntimeException("Cannot extend to different types of weight!");
		DataFlowPathSemiring other = (DataFlowPathSemiring) o;
		if (other.equals(one()))
			return this;
		if (this.equals(one()))
			return other;
		if (other.equals(zero()) || this.equals(zero())) {
			return zero();
		}
		Set<Statement> newAllStatements = new HashSet<>();
		newAllStatements.addAll(allStatements);
		newAllStatements.addAll(other.allStatements);
		return new DataFlowPathSemiring(newAllStatements, other.lastStatements);
	}

	@Override
	public Semiring combineWith(Semiring other) {
		return extendWith(other);
	}

	@Override
	public String value() {
		return this.rep;
	}

	public static DataFlowPathSemiring one() {
		if (one == null)
			one = new DataFlowPathSemiring("<ONE>");
		return one;
	}

	public static DataFlowPathSemiring zero() {
		if (zero == null)
			zero = new DataFlowPathSemiring("<ZERO>");
		return zero;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((allStatements == null) ? 0 : allStatements.hashCode());
		result = prime * result + ((lastStatements == null) ? 0 : lastStatements.hashCode());
		result = prime * result + ((rep == null) ? 0 : rep.hashCode());
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
		DataFlowPathSemiring other = (DataFlowPathSemiring) obj;
		if (allStatements == null) {
			if (other.allStatements != null)
				return false;
		} else if (!allStatements.equals(other.allStatements))
			return false;
		if (lastStatements == null) {
			if (other.lastStatements != null)
				return false;
		} else if (!lastStatements.equals(other.lastStatements))
			return false;
		if (rep == null) {
			if (other.rep != null)
				return false;
		} else if (!rep.equals(other.rep))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "\nLast relevant: " + lastStatements + "\nAll statements: " + allStatements;
	}
}

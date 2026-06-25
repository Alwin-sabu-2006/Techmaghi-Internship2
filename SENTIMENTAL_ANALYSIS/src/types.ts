/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface AnalysisResult {
  sentiment: 'positive' | 'negative' | 'neutral';
  emoji: string;
  expression: string;
  explanation: string;
}

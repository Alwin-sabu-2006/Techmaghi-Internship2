import { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Smile, AlertCircle, Loader2 } from 'lucide-react';
import { AnalysisResult } from './types';

export default function App() {
  const [text, setText] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);

  const handleAnalyze = async () => {
    if (!text.trim()) {
      setError('Please enter some text first!');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text }),
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.error || 'Failed to analyze text.');
      }

      const data: AnalysisResult = await response.json();
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Something went wrong. Please check your setup.');
    } finally {
      setLoading(false);
    }
  };

  const getSentimentColor = (sentiment: string) => {
    switch (sentiment) {
      case 'positive':
        return 'text-emerald-600 bg-emerald-50 border-emerald-100';
      case 'negative':
        return 'text-rose-600 bg-rose-50 border-rose-100';
      default:
        return 'text-slate-600 bg-slate-50 border-slate-100';
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col justify-between text-slate-800">
      {/* Navigation Header */}
      <header className="bg-white border-b border-slate-200 py-4 px-6 shadow-xs">
        <div className="max-w-2xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Smile className="w-6 h-6 text-indigo-500" />
            <h1 className="text-lg font-bold text-slate-900">Sentiment Analyzer</h1>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-xl w-full mx-auto px-4 py-8 flex-1 flex flex-col justify-center">
        <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm space-y-6">
          <div className="space-y-1">
            <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">Your Sentence</label>
            <textarea
              id="sentiment-textarea"
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="Type or paste any sentence here..."
              rows={4}
              disabled={loading}
              className="w-full text-slate-800 bg-slate-50 border border-slate-200 rounded-xl p-3 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-100 focus:border-indigo-500 transition-all resize-none"
            />
          </div>

          <button
            id="btn-submit"
            onClick={handleAnalyze}
            disabled={loading || !text.trim()}
            className="w-full bg-indigo-600 hover:bg-indigo-700 disabled:bg-slate-100 disabled:text-slate-400 text-white font-semibold text-sm py-3 px-4 rounded-xl transition-colors cursor-pointer flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Checking...</span>
              </>
            ) : (
              <span>Analyze Sentiment</span>
            )}
          </button>

          {/* Error Message */}
          {error && (
            <div className="p-4 bg-rose-50 border border-rose-100 rounded-xl flex items-start gap-2.5 text-rose-800">
              <AlertCircle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
              <div className="text-xs leading-relaxed font-semibold">{error}</div>
            </div>
          )}

          {/* Results Output */}
          <AnimatePresence mode="wait">
            {result && (
              <motion.div
                key={result.explanation}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                className="pt-6 border-t border-slate-100 space-y-4"
              >
                <div className="text-center space-y-2">
                  <div className="text-5xl">{result.emoji}</div>
                  <div className="flex items-center justify-center gap-2">
                    <span className="text-xs font-bold text-slate-400 uppercase">Sentiment:</span>
                    <span className={`px-2.5 py-0.5 rounded text-xs font-bold uppercase tracking-wider border ${getSentimentColor(result.sentiment)}`}>
                      {result.sentiment}
                    </span>
                  </div>
                  <div>
                    <span className="text-xs font-bold text-slate-400 uppercase mr-1.5">Expression:</span>
                    <span className="text-sm font-bold text-slate-800">{result.expression}</span>
                  </div>
                </div>

                <div className="bg-slate-50 border border-slate-100 rounded-xl p-4">
                  <p className="text-xs font-bold text-slate-400 uppercase mb-1">Explanation</p>
                  <p className="text-xs md:text-sm text-slate-600 leading-relaxed font-medium">
                    {result.explanation}
                  </p>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </main>

      {/* Footer */}
      <footer className="py-6 text-center text-xs text-slate-400 border-t border-slate-100 bg-white">
        <p>Sentiment Analyzer web app.</p>
      </footer>
    </div>
  );
}

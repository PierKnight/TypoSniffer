import numpy as np
from collections import Counter
import math

from typosniffer.config.config import get_config

def combined_ngrams(s, ns=[2,3]):
    """Generate combined character n-grams for multiple n values"""
    ngram_list = []
    for n in ns:
        ngram_list.extend([s[i:i+n] for i in range(len(s)-n+1)])
    return ngram_list

def compute_tf(doc_ngrams):
    """Compute term frequency for a document"""
    counts = Counter(doc_ngrams)
    total = sum(counts.values())
    return {term: count / total for term, count in counts.items()}

def compute_idf(corpus_ngrams_list):
    """Compute inverse document frequency across corpus"""
    N = len(corpus_ngrams_list)
    idf = {}
    all_terms = set(term for doc in corpus_ngrams_list for term in doc)
    for term in all_terms:
        df = sum(1 for doc in corpus_ngrams_list if term in doc)
        idf[term] = math.log((N + 1) / (df + 1)) + 1  # smoothing
    return idf

def compute_tfidf(tf, idf):
    """Compute TF-IDF vector"""
    return {term: tf.get(term, 0) * idf.get(term, 0) for term in idf.keys()}

def cosine_similarity(vec1, vec2):
    """Compute cosine similarity between two TF-IDF vectors"""
    terms = set(vec1.keys()) | set(vec2.keys())
    v1 = np.array([vec1.get(t,0) for t in terms])
    v2 = np.array([vec2.get(t,0) for t in terms])
    norm1 = np.linalg.norm(v1)
    norm2 = np.linalg.norm(v2)
    if norm1 == 0 or norm2 == 0:
        return 0.0
    return np.dot(v1, v2) / (norm1 * norm2)

def cosine_similarity_string(s1, s2):

    ngram = get_config().discovery.criteria.tf_idf_ngram

    corpus_ngrams = [combined_ngrams(s1, ns=ngram), combined_ngrams(s2, ns=ngram)]

    idfs = compute_idf(corpus_ngrams)
    tf1 = compute_tf(corpus_ngrams[0])
    tf2 = compute_tf(corpus_ngrams[1])
    tfidf1 = compute_tfidf(tf1, idfs)
    tfidf2 = compute_tfidf(tf2, idfs)

    sim = cosine_similarity(tfidf1, tfidf2)

    return sim

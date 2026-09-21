-- core/templates/abuse.lua
-- Automated abuse / scraping question. TypeSafe Noul (yes/no).
return {
  instructions = "Does this request look like automated abuse of an LLM "
    .. "endpoint: bulk scraping, credential stuffing via prompts, spam "
    .. "generation, or resource exhaustion, rather than a genuine user request?",
  criteria = {
    [true]  = "Templated or machine-generated text, mass-production requests, "
      .. "requests to generate spam or phishing at scale, or nonsense filler "
      .. "designed only to consume tokens.",
    [false] = "A plausible single-user request, even if repetitive in style.",
  },
}

#!/bin/sh
# Download the sources bench/tools/build.py reads into $1 (default
# bench/tools/raw, gitignored): tool definitions of public MCP servers, agent
# frameworks and function-calling examples, each file pinned to a commit.
# Read-only GitHub API calls (`gh api`, GET). Licenses: README.md.
set -eu
RAW=${1:-bench/tools/raw}
mkdir -p "$RAW"

# get <dest> <owner/repo> <commit> <path>
get() {
  [ -s "$RAW/$1" ] && return 0
  gh api -H "Accept: application/vnd.github.raw" "repos/$2/contents/$4?ref=$3" > "$RAW/$1.tmp"
  mv "$RAW/$1.tmp" "$RAW/$1"
}

MCP=f46d9578190b476b3501923ea8977d899e8db2cb    # modelcontextprotocol/servers
ARC=9be4674d1ddf8c469e6461a27a337eeb65f76c2e    # modelcontextprotocol/servers-archived
GHM=85598ba6e1256f7ebf4867b95d63b833c4549264    # github/github-mcp-server
get mcp_filesystem.ts modelcontextprotocol/servers $MCP src/filesystem/index.ts
get mcp_fetch.py modelcontextprotocol/servers $MCP src/fetch/src/mcp_server_fetch/server.py
get mcp_git.py modelcontextprotocol/servers $MCP src/git/src/mcp_server_git/server.py
get mcp_memory.ts modelcontextprotocol/servers $MCP src/memory/index.ts
get mcp_sequentialthinking.ts modelcontextprotocol/servers $MCP src/sequentialthinking/index.ts
get mcp_time.py modelcontextprotocol/servers $MCP src/time/src/mcp_server_time/server.py
for s in slack puppeteer postgres brave-search google-maps gdrive aws-kb-retrieval-server; do
  get arch_$s.ts modelcontextprotocol/servers-archived $ARC src/$s/index.ts
done
get arch_redis.ts modelcontextprotocol/servers-archived $ARC src/redis/src/index.ts
get arch_sqlite.py modelcontextprotocol/servers-archived $ARC src/sqlite/src/mcp_server_sqlite/server.py
get arch_sentry.py modelcontextprotocol/servers-archived $ARC src/sentry/src/mcp_server_sentry/server.py
# the server's default toolsets (context, repos, issues, pull_requests, users), README at the same commit
get ghmcp_README.md github/github-mcp-server $GHM README.md
for t in get_me get_team_members get_teams \
         create_branch create_or_update_file create_repository delete_file delete_repository fork_repository \
         get_commit get_file_contents get_latest_release get_release_by_tag get_tag list_branches list_commits \
         list_releases list_repository_collaborators list_tags push_files search_code search_commits search_repositories \
         add_issue_comment get_label issue_read issue_write list_issue_fields list_issue_types list_issues \
         search_issues sub_issue_write update_issue_comment \
         add_comment_to_pending_review add_reply_to_pull_request_comment create_pull_request list_pull_requests \
         merge_pull_request pull_request_read pull_request_review_write search_pull_requests update_pull_request \
         update_pull_request_branch search_users; do
  get ghmcp_$t.snap github/github-mcp-server $GHM pkg/github/__toolsnaps__/$t.snap
done
get playwright_README.md microsoft/playwright-mcp f1257a5a67aff872f947fae274759f7d54853862 README.md
get firecrawl_v1.12.0.ts firecrawl/firecrawl-mcp-server 1b9c89b502a04d7c6383b20484dabdf67a326363 src/index.ts
get tavily.ts tavily-ai/tavily-mcp 1c1d54c2a619afe52544f775c8d82a56ac6d8bb5 src/index.ts
C7=e275a848a420e0d11c2822f61201ee005bfd1133
get context7.ts upstash/context7 $C7 packages/mcp/src/index.ts
get context7_tool-names.ts upstash/context7 $C7 packages/mcp/src/lib/tool-names.ts
EXA=f3d71fb6b0ff4b4683f108f05bc2bae61a9f7e97
get exa_webSearch.ts exa-labs/exa-mcp-server $EXA src/tools/webSearch.ts
get exa_webFetch.ts exa-labs/exa-mcp-server $EXA src/tools/webFetch.ts

OH=7fbb48c40679afd674970966b96185657d92a487     # OpenHands 0.62.0, the last CodeAct agent
for f in bash str_replace_editor ipython think finish task_tracker security_utils prompt browser; do
  get openhands_$f.py OpenHands/OpenHands $OH openhands/agenthub/codeact_agent/tools/$f.py
done
# which of them the agent sends by default (_get_tools, AgentConfig)
get openhands_codeact_agent.py OpenHands/OpenHands $OH openhands/agenthub/codeact_agent/codeact_agent.py
get openhands_agent_config.py OpenHands/OpenHands $OH openhands/core/config/agent_config.py
get openhands_tool_names.py OpenHands/OpenHands $OH openhands/llm/tool_names.py
SWE=3ea751c087f32b16e039a2233dd6eefecef325d5
get swe_default.yaml SWE-agent/SWE-agent $SWE config/default.yaml
get swe_commands.py SWE-agent/SWE-agent $SWE sweagent/tools/commands.py
for b in edit_anthropic review_on_submit_m registry; do
  get swe_$b.yaml SWE-agent/SWE-agent $SWE tools/$b/config.yaml
done
CON=5522c6f44ca0ac3528b37244818fbfa39b5af470
for f in readFile createNewFile runTerminalCommand globSearch grepSearch ls fetchUrlContent searchWeb viewDiff \
         readCurrentlyOpenFile singleFindAndReplace viewSubdirectory viewRepoMap codebaseTool createRuleBlock \
         requestRule multiEdit readFileRange readSkill editFile; do
  get continue_$f.ts continuedev/continue $CON core/tools/definitions/$f.ts
done
get continue_builtIn.ts continuedev/continue $CON core/tools/builtIn.ts
# which of them agent mode sends
get continue_tools_index.ts continuedev/continue $CON core/tools/index.ts

OCB=5986832a554169dc87285b1b0b396941f235a62e
for n in How_to_call_functions_with_chat_models Using_tool_required_for_customer_service \
         Function_calling_finding_nearby_places How_to_call_functions_for_knowledge_retrieval Structured_Outputs_Intro; do
  get cookbook_$n.ipynb openai/openai-cookbook $OCB examples/$n.ipynb
done
get claude_customer_service_agent.ipynb anthropics/claude-cookbooks 813fbeec03cdedfda7808529438d1c7af71f26eb \
  tool_use/customer_service_agent.ipynb
get bfcl_live_multiple.json ShishirPatil/gorilla 6ea57973c7a6097fd7c5915698c54c17c5b1b6c8 \
  berkeley-function-call-leaderboard/bfcl_eval/data/BFCL_v4_live_multiple.json
LCC=f425a3ed1933173fb3694b81359d1519c4f82d36
for f in copy delete file_search list_dir move read write; do
  get langchain_fm_$f.py langchain-ai/langchain-community $LCC libs/community/langchain_community/tools/file_management/$f.py
done
for f in tavily_search wikipedia requests shell; do
  get langchain_$f.py langchain-ai/langchain-community $LCC libs/community/langchain_community/tools/$f/tool.py
done
LI=cf8311c42dfe57bcd6bf106424481c808307ee61
get llama_gmail.py run-llama/llama_index $LI \
  llama-index-integrations/tools/llama-index-tools-google/llama_index/tools/google/gmail/base.py
get llama_wikipedia.py run-llama/llama_index $LI \
  llama-index-integrations/tools/llama-index-tools-wikipedia/llama_index/tools/wikipedia/base.py
OAG=265f16fa369df61c0074a08dcb1af644cfd00303
get agents_customer_service.py openai/openai-agents-python $OAG examples/customer_service/main.py
# how a handoff becomes a tool: its description and its (empty, strict) schema
get agents_handoffs.py openai/openai-agents-python $OAG src/agents/handoffs/__init__.py
get agents_strict_schema.py openai/openai-agents-python $OAG src/agents/strict_schema.py
echo "sources in $RAW"

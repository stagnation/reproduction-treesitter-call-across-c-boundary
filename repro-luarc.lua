vim.loader.enable()

vim.g.coq_settings = {
    ["auto_start"] = "shut-up",
}

require('nvim-treesitter.configs').setup {
    highlight = {
        enable = true,
        additional_vim_regex_highlighting = false,
    },
}

local on_attach = function(client, bufnr)
    -- TODO: the github page says to use an Auto Command instead of the
    -- callback
    local function buf_set_keymap(...) vim.api.nvim_buf_set_keymap(bufnr, ...) end
    local function buf_set_option(...) vim.api.nvim_buf_set_option(bufnr, ...) end

    buf_set_option('omnifunc', 'v:lua.vim.lsp.omnifunc')
end

local capabilities = vim.lsp.protocol.make_client_capabilities()

vim.lsp.enable('pylsp')
vim.lsp.config('pylsp', {
    capabilities = capabilities,
    on_attach = on_attach,
    cmd = {"pylsp", "--verbose", "--log-file=/tmp/lsp/pylsp.log"},
    settings = {
        pylsp = {
            plugins = {
                mccabe = { enabled = false }
            }
        }
    }
})

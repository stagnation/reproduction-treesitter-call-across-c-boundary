let plug_location = '~/.vim/plugged'
if has ('nvim')
    let plug_location = '~/.local/share/nvim/plugged'
endif

call plug#begin(plug_location)

Plug 'ms-jpq/coq_nvim',                         {'branch': 'coq', 'do': ':COQdeps'}
Plug 'nvim-treesitter/nvim-treesitter',         {'do': ':TSUpdate' }
Plug 'nvim-treesitter/nvim-treesitter-context', {}
Plug 'andymass/vim-matchup',                    {}
Plug 'neovim/nvim-lspconfig',                   {}

call plug#end()

lua dofile('/home/nwirekli/task/vim/treesitter-call-across-c-boundary/repro-luarc.lua')


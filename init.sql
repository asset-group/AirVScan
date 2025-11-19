create table llm_res (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    exp_id TEXT not null,
    device TEXT not null,
    protocol TEXT not null,
    case_type TEXT not null, -- mut / dup / benign
    n_field TEXT not null, -- '' / 1-field / 2-field
    noise_type TEXT not null, -- normal / noise
    prompt_type TEXT not null, -- check_attack / root_cause
    prompt_mode TEXT not null, -- full / full+context / diff / diff+context
    prompt_path TEXT not null,
    model TEXT not null, -- gemini-2.5-pro
    -- 
    prompt TEXT not null, 
    prompt_hash TEXT not null,
    trial_idx TEXT not null, 
    ref_id int,
    res TEXT,
    res_correct boolean,
    reasoning_correct boolean
);

create index prompt_hash_model_idx on llm_res(prompt_hash, model, trial_idx);

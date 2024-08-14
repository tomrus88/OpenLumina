#pragma once

#include "pch.h"

struct plugin_ctx_t : public plugmod_t
{
	qvector<qstring> certificates;
	bool idaapi run(size_t arg) override;
	bool init_hook();
	~plugin_ctx_t() override;
};

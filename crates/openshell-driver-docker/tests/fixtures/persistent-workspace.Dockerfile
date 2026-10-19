# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
FROM alpine:3
RUN mkdir -p /workspace/project \
    && printf image-seed > /workspace/project/image-seed \
    && chown -R 1000:1000 /workspace
USER 1000:1000
WORKDIR /workspace/project

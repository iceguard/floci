package io.github.hectorvent.floci.core.storage;

import org.junit.jupiter.api.Test;

import java.util.Comparator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AccountAwareStorageBackendTest {

    @Test
    void crossAccountEntryScanPreservesOwnerAndDuplicateLogicalKeys() {
        InMemoryStorage<String, String> delegate = new InMemoryStorage<>();
        delegate.put("111111111111/region::command", "first");
        delegate.put("222222222222/region::command", "second");
        delegate.put("unprefixed-legacy", "unknown-owner");
        AccountAwareStorageBackend<String> storage =
                new AccountAwareStorageBackend<>(delegate, null, "000000000000");

        List<AccountAwareStorageBackend.AccountEntry<String>> entries =
                storage.scanAllAccountEntries().stream()
                        .sorted(Comparator.comparing(AccountAwareStorageBackend.AccountEntry::accountId))
                        .toList();

        assertEquals(List.of(
                new AccountAwareStorageBackend.AccountEntry<>(
                        "111111111111", "region::command", "first"),
                new AccountAwareStorageBackend.AccountEntry<>(
                        "222222222222", "region::command", "second")), entries);
    }
}

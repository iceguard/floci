package com.floci.test;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.CreateInstanceProfileRequest;
import software.amazon.awssdk.services.iam.model.DeleteInstanceProfileRequest;
import software.amazon.awssdk.services.iam.model.GetInstanceProfileRequest;
import software.amazon.awssdk.services.iam.model.ListInstanceProfileTagsRequest;
import software.amazon.awssdk.services.iam.model.NoSuchEntityException;
import software.amazon.awssdk.services.iam.model.Tag;
import software.amazon.awssdk.services.iam.model.TagInstanceProfileRequest;
import software.amazon.awssdk.services.iam.model.UntagInstanceProfileRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;

class IamInstanceProfileTagsTest {

    private IamClient iam;
    private String profileName;
    private String emptyProfileName;

    @BeforeEach
    void setUp() {
        iam = TestFixtures.iamClient();
        profileName = TestFixtures.uniqueName("sdk-profile-tags");
        emptyProfileName = TestFixtures.uniqueName("sdk-profile-empty");
    }

    @AfterEach
    void tearDown() {
        deleteIfPresent(profileName);
        deleteIfPresent(emptyProfileName);
        iam.close();
    }

    @Test
    void managesInstanceProfileTagsThroughOfficialSdk() {
        var created = iam.createInstanceProfile(CreateInstanceProfileRequest.builder()
                .instanceProfileName(profileName)
                .tags(
                        Tag.builder().key("owner").value("platform").build(),
                        Tag.builder().key("xml-special").value("edge<&\"'").build(),
                        Tag.builder().key("empty").value("").build())
                .build());
        assertThat(created.instanceProfile().instanceProfileName()).isEqualTo(profileName);

        assertThat(iam.getInstanceProfile(GetInstanceProfileRequest.builder()
                        .instanceProfileName(profileName)
                        .build()).instanceProfile().tags())
                .extracting(Tag::key, Tag::value)
                .containsExactlyInAnyOrder(
                        tuple("owner", "platform"),
                        tuple("xml-special", "edge<&\"'"),
                        tuple("empty", ""));

        iam.tagInstanceProfile(TagInstanceProfileRequest.builder()
                .instanceProfileName(profileName)
                .tags(
                        Tag.builder().key("owner").value("platform").build(),
                        Tag.builder().key("stage").value("runtime").build())
                .build());

        var listed = iam.listInstanceProfileTags(ListInstanceProfileTagsRequest.builder()
                .instanceProfileName(profileName)
                .build());
        assertThat(listed.tags())
                .extracting(Tag::key, Tag::value)
                .containsExactlyInAnyOrder(
                        tuple("owner", "platform"),
                        tuple("xml-special", "edge<&\"'"),
                        tuple("empty", ""),
                        tuple("stage", "runtime"));
        assertThat(listed.isTruncated()).isFalse();

        iam.untagInstanceProfile(UntagInstanceProfileRequest.builder()
                .instanceProfileName(profileName)
                .tagKeys("stage")
                .build());

        assertThat(iam.getInstanceProfile(GetInstanceProfileRequest.builder()
                        .instanceProfileName(profileName)
                        .build()).instanceProfile().tags())
                .extracting(Tag::key, Tag::value)
                .containsExactlyInAnyOrder(
                        tuple("owner", "platform"),
                        tuple("xml-special", "edge<&\"'"),
                        tuple("empty", ""));

        iam.createInstanceProfile(CreateInstanceProfileRequest.builder()
                .instanceProfileName(emptyProfileName)
                .build());
        var emptyProfile = iam.getInstanceProfile(GetInstanceProfileRequest.builder()
                .instanceProfileName(emptyProfileName)
                .build()).instanceProfile();
        assertThat(emptyProfile.hasTags()).isFalse();
        assertThat(emptyProfile.tags()).isEmpty();
        var emptyTags = iam.listInstanceProfileTags(ListInstanceProfileTagsRequest.builder()
                .instanceProfileName(emptyProfileName)
                .build());
        assertThat(emptyTags.tags()).isEmpty();
        assertThat(emptyTags.isTruncated()).isFalse();

        String missingProfile = TestFixtures.uniqueName("sdk-profile-missing");
        assertThatThrownBy(() -> iam.listInstanceProfileTags(ListInstanceProfileTagsRequest.builder()
                .instanceProfileName(missingProfile)
                .build())).isInstanceOf(NoSuchEntityException.class);
        assertThatThrownBy(() -> iam.tagInstanceProfile(TagInstanceProfileRequest.builder()
                .instanceProfileName(missingProfile)
                .tags(Tag.builder().key("owner").value("wrong").build())
                .build())).isInstanceOf(NoSuchEntityException.class);
        assertThatThrownBy(() -> iam.untagInstanceProfile(UntagInstanceProfileRequest.builder()
                .instanceProfileName(missingProfile)
                .tagKeys("owner")
                .build())).isInstanceOf(NoSuchEntityException.class);

        assertThat(iam.listInstanceProfileTags(ListInstanceProfileTagsRequest.builder()
                        .instanceProfileName(profileName)
                        .build()).tags())
                .extracting(Tag::key, Tag::value)
                .containsExactlyInAnyOrder(
                        tuple("owner", "platform"),
                        tuple("xml-special", "edge<&\"'"),
                        tuple("empty", ""));
    }

    private void deleteIfPresent(String name) {
        try {
            iam.deleteInstanceProfile(DeleteInstanceProfileRequest.builder()
                    .instanceProfileName(name)
                    .build());
        } catch (NoSuchEntityException ignored) {
            // Cleanup is idempotent when the test fails before profile creation.
        }
    }
}

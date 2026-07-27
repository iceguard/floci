/**
 * STS integration tests.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import {
  IAMClient,
  CreateRoleCommand,
  DeleteRoleCommand,
} from '@aws-sdk/client-iam';
import { STSClient, GetCallerIdentityCommand, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { makeClient, ACCOUNT } from './setup';

describe('STS', () => {
  const roleName = 'test-role';
  let sts: STSClient;
  let iam: IAMClient;

  beforeAll(async () => {
    sts = makeClient(STSClient);
    iam = makeClient(IAMClient);
    await iam.send(new CreateRoleCommand({
      RoleName: roleName,
      AssumeRolePolicyDocument: JSON.stringify({
        Version: '2012-10-17',
        Statement: [{
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 'sts:AssumeRole',
        }],
      }),
    }));
  });

  afterAll(async () => {
    await iam.send(new DeleteRoleCommand({ RoleName: roleName }));
    iam.destroy();
    sts.destroy();
  });

  it('should get caller identity', async () => {
    const response = await sts.send(new GetCallerIdentityCommand({}));
    expect(response.Account).toBeTruthy();
    expect(response.UserId).toBeTruthy();
  });

  it('should assume role', async () => {
    const response = await sts.send(
      new AssumeRoleCommand({
        RoleArn: `arn:aws:iam::${ACCOUNT}:role/${roleName}`,
        RoleSessionName: 'test-session',
      })
    );
    expect(response.Credentials?.AccessKeyId).toBeTruthy();
  });
});
